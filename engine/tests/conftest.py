"""Import fairsim first, so it pins NumPy's CPU dispatch before any test module imports NumPy."""

import fairsim  # noqa: F401
