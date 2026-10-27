__version__ = "0.1.0"

try:  # verify HTTPS against the operating system's trusted certificates
    import truststore

    truststore.inject_into_ssl()
except ImportError:
    pass
