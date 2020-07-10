
from chaum.test import test_asymmetric
from chaum.test import test_hybrid
from chaum.test import test_routing


def test():
    test_asymmetric.test()
    test_hybrid.test()
    test_routing.test()


if __name__ == '__main__':
    test()
