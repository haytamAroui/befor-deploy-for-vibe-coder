def load(path):
    try:
        return open(path).read()
    except Exception:
        return None

def remove(path):
    try:
        delete(path)
    except ValueError:
        pass
