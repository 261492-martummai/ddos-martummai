import os


def is_root_privileged():
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Bypass Windows UAC check by trying to open a privileged system file
        return True
