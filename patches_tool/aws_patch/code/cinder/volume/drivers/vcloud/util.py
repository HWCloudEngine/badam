'''
Created on 2015.3.11

@author: Administrator
'''
# Copyright (c) 2011 Citrix Systems, Inc.
# Copyright 2011 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Classes to handle image files

Collection of classes to handle image upload/download to/from Image service
(like Glance image storage and retrieval service) from/to ESX/ESXi server.

"""


# import six.moves.urllib.parse as urlparse
from eventlet import event
from eventlet import greenthread
from eventlet import queue
from eventlet import timeout

from cinder import exception
from cinder.i18n import _
from cinder.openstack.common import log as logging

import contextlib
import os
import tempfile

from oslo.config import cfg

from cinder import exception
from cinder.openstack.common import fileutils
from cinder.openstack.common import imageutils
# from cinder.openstack.common import processutils
from cinder.openstack.common import timeutils
from cinder.openstack.common import units
from cinder import utils
from cinder.volume import utils as volume_utils


LOG = logging.getLogger(__name__)
IO_THREAD_SLEEP_TIME = .01
GLANCE_POLL_INTERVAL = 5

READ_CHUNKSIZE = 65536
QUEUE_BUFFER_SIZE = 10


image_helper_opt = [cfg.StrOpt('image_conversion_dir',
                               default='$state_path/conversion',
                               help='Directory used for temporary storage '
                                    'during image conversion'), ]
CONF = cfg.CONF
CONF.register_opts(image_helper_opt)

class GlanceFileRead(object):
    """Glance file read handler class."""

    def __init__(self, glance_read_iter):
        self.glance_read_iter = glance_read_iter
        self.iter = self.get_next()

    def read(self, chunk_size):
        """Read an item from the queue.

        The chunk size is ignored for the Client ImageBodyIterator
        uses its own CHUNKSIZE.
        """
        try:
            return self.iter.next()
        except StopIteration:
            return ""

    def get_next(self):
        """Get the next item from the image iterator."""
        for data in self.glance_read_iter:
            yield data

    def close(self):
        """A dummy close just to maintain consistency."""
        pass


class HybridFileHandle(file):

    def __init__(self, *args):
        self.file = open(*args)

    def read(self, *args, **kwargs):
        return self.file.read(READ_CHUNKSIZE)

class GlanceWriteThread(object):
    """Ensures that image data is written to in the glance client and that
    it is in correct ('active')state.
    """

    def __init__(self, context, input_file, image_service, image_id,
                 image_meta=None):
        if not image_meta:
            image_meta = {}

        self.context = context
        self.input_file = input_file
        self.image_service = image_service
        self.image_id = image_id
        self.image_meta = image_meta
        self._running = False

    def start(self):
        self.done = event.Event()

        def _inner():
            """Initiate write thread.

            Function to do the image data transfer through an update
            and thereon checks if the state is 'active'.
            """
            LOG.debug("Initiating image service update on image: %(image)s "
                      "with meta: %(meta)s" % {'image': self.image_id,
                                               'meta': self.image_meta})

            try:
                self.image_service.update(self.context,
                                          self.image_id,
                                          self.image_meta,
                                          data=self.input_file)

                self._running = True
                while self._running:
                    image_meta = self.image_service.show(self.context,
                                                         self.image_id)
                    image_status = image_meta.get('status')
                    if image_status == 'active':
                        self.stop()
                        LOG.debug("Glance image: %s is now active." %
                                  self.image_id)
                        self.done.send(True)
                    # If the state is killed, then raise an exception.
                    elif image_status == 'killed':
                        self.stop()
                        msg = (_("Glance image: %s is in killed state.") %
                               self.image_id)
                        LOG.error(msg)
                        excep = ImageTransferException(msg)
                        self.done.send_exception(excep)
                    elif image_status in ['saving', 'queued']:
                        greenthread.sleep(GLANCE_POLL_INTERVAL)
                    else:
                        self.stop()
                        msg = _("Glance image %(id)s is in unknown state "
                                "- %(state)s") % {'id': self.image_id,
                                                  'state': image_status}
                        LOG.error(msg)
                        excep = ImageTransferException(msg)
                        self.done.send_exception(excep)
            except Exception as ex:
                self.stop()
                msg = (_("Error occurred while writing to image: %s") %
                       self.image_id)
                LOG.exception(msg)
                excep = ImageTransferException(ex)
                self.done.send_exception(excep)

        greenthread.spawn(_inner)
        return self.done

    def stop(self):
        self._running = False

    def wait(self):
        return self.done.wait()

    def close(self):
        pass


class IOThread(object):
    """Class that reads chunks from the input file and writes them to the
    output file till the transfer is completely done.
    """

    def __init__(self, input, output):
        self.input = input
        self.output = output
        self._running = False
        self.got_exception = False

    def start(self):
        self.done = event.Event()

        def _inner():
            """Read data from the input and write the same to the output
            until the transfer completes.
            """
            self._running = True
            while self._running:
                try:
                    data = self.input.read(READ_CHUNKSIZE)

                    if not data:
                        self.stop()
                        self.done.send(True)
                    self.output.write(data)
                    greenthread.sleep(IO_THREAD_SLEEP_TIME)
                except Exception as exc:
                    self.stop()
                    LOG.exception(exc)
                    self.done.send_exception(exc)

        greenthread.spawn(_inner)
        return self.done

    def stop(self):
        self._running = False

    def wait(self):
        return self.done.wait()

class ThreadSafePipe(queue.LightQueue):
    """The pipe to hold the data which the reader writes to and the writer
    reads from.
    """

    def __init__(self, maxsize, transfer_size):
        queue.LightQueue.__init__(self, maxsize)
        self.transfer_size = transfer_size
        self.transferred = 0

    def read(self, chunk_size):
        """Read data from the pipe.

        Chunksize if ignored for we have ensured
        that the data chunks written to the pipe by readers is the same as the
        chunks asked for by the Writer.
        """
        if self.transferred < self.transfer_size:
            data_item = self.get()
            self.transferred += len(data_item)
            return data_item
        else:
            return ""

    def write(self, data):
        """Put a data item in the pipe."""
        self.put(data)

    def seek(self, offset, whence=0):
        """Set the file's current position at the offset."""
        pass

    def tell(self):
        """Get size of the file to be read."""
        return self.transfer_size

    def close(self):
        """A place-holder to maintain consistency."""
        pass



def start_transfer(context, timeout_secs, read_file_handle, max_data_size,
                   write_file_handle=None, image_service=None, image_id=None,
                   image_meta=None):
    """Start the data transfer from the reader to the writer.

    Reader writes to the pipe and the writer reads from the pipe. This means
    that the total transfer time boils down to the slower of the read/write
    and not the addition of the two times.
    """

    if not image_meta:
        image_meta = {}

    # The pipe that acts as an intermediate store of data for reader to write
    # to and writer to grab from.
    thread_safe_pipe = ThreadSafePipe(QUEUE_BUFFER_SIZE, max_data_size)
    # The read thread. In case of glance it is the instance of the
    # GlanceFileRead class. The glance client read returns an iterator
    # and this class wraps that iterator to provide datachunks in calls
    # to read.
    read_thread = IOThread(read_file_handle, thread_safe_pipe)

    # In case of Glance - VMware transfer, we just need a handle to the
    # HTTP Connection that is to send transfer data to the VMware datastore.
    if write_file_handle:
        write_thread = IOThread(thread_safe_pipe, write_file_handle)
    # In case of VMware - Glance transfer, we relinquish VMware HTTP file read
    # handle to Glance Client instance, but to be sure of the transfer we need
    # to be sure of the status of the image on glance changing to active.
    # The GlanceWriteThread handles the same for us.
    elif image_service and image_id:
        write_thread = GlanceWriteThread(context, thread_safe_pipe,
                                                 image_service, image_id,
                                                 image_meta)
    # Start the read and write threads.
    read_event = read_thread.start()
    write_event = write_thread.start()
    timer = timeout.Timeout(timeout_secs)
    try:
        # Wait on the read and write events to signal their end
        read_event.wait()
        write_event.wait()
    except (timeout.Timeout, Exception) as exc:
        # In case of any of the reads or writes raising an exception,
        # stop the threads so that we un-necessarily don't keep the other one
        # waiting.
        read_thread.stop()
        write_thread.stop()

        # Log and raise the exception.
        LOG.exception(_("Error occurred during image transfer."))
        # if isinstance(exc, error_util.ImageTransferException):
        #     raise
        # raise error_util.ImageTransferException(exc)
    finally:
        timer.cancel()
        # No matter what, try closing the read and write handles, if it so
        # applies.
        read_file_handle.close()
        if write_file_handle:
            write_file_handle.close()



class ImageTransferException(exception.CinderException):
    """Thrown when there is an error during image transfer."""
    message = _("Error occurred during image transfer.")

def upload_volume(context, image_service, image_meta, volume_path,
                  volume_format='raw'):
    image_id = image_meta['id']
    if (image_meta['disk_format'] == volume_format):
        LOG.debug("%s was %s, no need to convert to %s" %
                  (image_id, volume_format, image_meta['disk_format']))
        if os.name == 'nt' or os.access(volume_path, os.R_OK):
            with fileutils.file_open(volume_path, 'rb') as image_file:
                image_service.update(context, image_id, {}, image_file)
        else:
            with utils.temporary_chown(volume_path):
                with fileutils.file_open(volume_path) as image_file:
                    image_service.update(context, image_id, {}, image_file)
        return

    if (CONF.image_conversion_dir and not
            os.path.exists(CONF.image_conversion_dir)):
        os.makedirs(CONF.image_conversion_dir)

    fd, tmp = tempfile.mkstemp(dir=CONF.image_conversion_dir)
    os.close(fd)
    with fileutils.remove_path_on_error(tmp):
        LOG.debug("%s was %s, converting to %s" %
                  (image_id, volume_format, image_meta['disk_format']))
        convert_image(volume_path, tmp, image_meta['disk_format'],
                      bps_limit=CONF.volume_copy_bps_limit,is_qcow_compress=True)

        data = qemu_img_info(tmp)
        if data.file_format != image_meta['disk_format']:
            raise exception.ImageUnacceptable(
                image_id=image_id,
                reason=_("Converted to %(f1)s, but format is now %(f2)s") %
                {'f1': image_meta['disk_format'], 'f2': data.file_format})

        with fileutils.file_open(tmp, 'rb') as image_file:
            image_service.update(context, image_id, {}, image_file)
        fileutils.delete_if_exists(tmp)

def convert_image(source, dest, out_format, bps_limit=None, is_qcow_compress=False):
    """Convert image to other format."""

    cmd = ('qemu-img', 'convert',
           '-O', out_format, source, dest)

    if is_qcow_compress and out_format=='qcow2':
        cmd = ('qemu-img', 'convert',
               '-c',
               '-O', out_format, source, dest)
    else:
        cmd = ('qemu-img', 'convert',
               '-O', out_format, source, dest)

    # Check whether O_DIRECT is supported and set '-t none' if it is
    # This is needed to ensure that all data hit the device before
    # it gets unmapped remotely from the host for some backends
    # Reference Bug: #1363016

    # NOTE(jdg): In the case of file devices qemu does the
    # flush properly and more efficiently than would be done
    # setting O_DIRECT, so check for that and skip the
    # setting for non BLK devs
    if (utils.is_blk_device(dest) and
            volume_utils.check_for_odirect_support(source,
                                                   dest,
                                                   'oflag=direct')):
        cmd = ('qemu-img', 'convert',
               '-t', 'none',
               '-O', out_format, source, dest)

    start_time = timeutils.utcnow()
    cgcmd = volume_utils.setup_blkio_cgroup(source, dest, bps_limit)
    if cgcmd:
        cmd = tuple(cgcmd) + cmd
    utils.execute(*cmd, run_as_root=True)

    duration = timeutils.delta_seconds(start_time, timeutils.utcnow())

    # NOTE(jdg): use a default of 1, mostly for unit test, but in
    # some incredible event this is 0 (cirros image?) don't barf
    if duration < 1:
        duration = 1
    fsz_mb = os.stat(source).st_size / units.Mi
    mbps = (fsz_mb / duration)
    msg = ("Image conversion details: src %(src)s, size %(sz).2f MB, "
           "duration %(duration).2f sec, destination %(dest)s")
    LOG.debug(msg % {"src": source,
                     "sz": fsz_mb,
                     "duration": duration,
                     "dest": dest})

    msg = _("Converted %(sz).2f MB image at %(mbps).2f MB/s")
    LOG.info(msg % {"sz": fsz_mb, "mbps": mbps})

def qemu_img_info(path):
    """Return an object containing the parsed output from qemu-img info."""
    cmd = ('env', 'LC_ALL=C', 'qemu-img', 'info', path)
    if os.name == 'nt':
        cmd = cmd[2:]
    out, err = utils.execute(*cmd, run_as_root=True)
    return imageutils.QemuImgInfo(out)