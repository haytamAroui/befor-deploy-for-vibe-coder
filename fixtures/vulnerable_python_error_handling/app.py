def load(path):
    try:
        return open(path).read()
    except Exception:
        pass

def remove(path):
    try:
        delete(path)
    except:
        pass
