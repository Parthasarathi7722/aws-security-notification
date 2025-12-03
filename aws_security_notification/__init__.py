# Expose the Lambda handler for library usage
# Import the installed top-level module so this works after pip install
import SecOps_notification as _mod

lambda_handler = _mod.lambda_handler
