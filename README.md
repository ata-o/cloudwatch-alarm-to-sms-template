# cloudwatch-alarm-to-sms-template
A code snippet for AWS Lambda to convert a cloudwatch alert to any notification format, works for AWS SNS and Web Hooks, includes Slack and Opsgenie.

## Usage
Paste the code to a lambda function, add webhook & sns subscription as environment variables. See test.json for a dummy cloudwatch event.
