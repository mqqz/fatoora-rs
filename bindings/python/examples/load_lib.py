# --8<-- [start:example]
from fatoora import Config, Environment

with Config(Environment.NON_PRODUCTION) as config:
    assert config.env() == Environment.NON_PRODUCTION
# --8<-- [end:example]
