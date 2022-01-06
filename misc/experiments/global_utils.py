from abc import ABC

__DRY_RUN = False


def dry_run_on():
    global __DRY_RUN
    __DRY_RUN = True


def dry_run_off():
    global __DRY_RUN
    __DRY_RUN = False


def dry_run():
    return __DRY_RUN


def singleton(real_cls):
    class SingletonFactory(ABC):
        instance = None

        def __new__(cls, *args, **kwargs):
            if not cls.instance:
                cls.instance = real_cls(*args, **kwargs)
            return cls.instance

    SingletonFactory.register(real_cls)
    return SingletonFactory


@singleton
class GlobalConf(object):
    def __init__(self):
        self.timeout = 120
        self.delay_time = 100
        self.nb_runs = 10
