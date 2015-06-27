from install_tool import log

log_dict = {}

class localLog():
    def __int__(self):
        pass

    @staticmethod
    def get_logger(file_name):
        log.init(file_name)
        return log