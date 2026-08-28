def load(path):
    try:
        return open(path).read()
    except OSError:
        raise RuntimeError("unable to load")

def remove(path):
    try:
        delete(path)
    except Exception as error:
        log_error(error)
