"""
Test Factory to make fake objects for testing
"""
from datetime import date
from uuid import uuid4

import factory
from factory.fuzzy import FuzzyDate, FuzzyChoice

from service.models import Account


class AccountFactory(factory.Factory):
    """Creates fake Accounts."""

    # pylint: disable=too-few-public-methods
    class Meta:
        """Persistent class for factory."""
        model = Account

    id = factory.LazyAttribute(lambda o: uuid4())
    name = factory.Faker('name')
    email = factory.Faker('email')
    gender = FuzzyChoice(['male', 'female', 'other'])
    address = factory.Faker('address')
    phone_number = factory.Faker('phone_number')
    date_joined = FuzzyDate(date(2008, 1, 1))
    user_id = factory.LazyAttribute(lambda o: uuid4())
