"""
SIEM Simulator Module
Generates realistic security alerts in various SIEM formats.
"""
from siem_simulator.simulator import (
    SIEMSimulator,
    simulator,
    generate_demo_data
)
from siem_simulator.scenarios import (
    SCENARIOS,
    list_scenarios,
    get_scenario,
    get_random_scenario
)
from siem_simulator.formats import (
    FORMAT_GENERATORS,
    get_format_generator
)
from siem_simulator.router import router as simulator_router

__all__ = [
    'SIEMSimulator',
    'simulator',
    'generate_demo_data',
    'SCENARIOS',
    'list_scenarios',
    'get_scenario',
    'get_random_scenario',
    'FORMAT_GENERATORS',
    'get_format_generator',
    'simulator_router'
]
