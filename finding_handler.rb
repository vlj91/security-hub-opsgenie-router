# https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html

require 'json'
require 'logger'

def log
  @log ||= Logger.new($stdout)
end

# https://docs.opsgenie.com/docs/alert-api#create-alert
ALERT_DESCRIPTION_LIMIT = 15000
ALERT_MESSAGE_LIMIT = 130
ALERT_DETAILS_LIMIT = 8000
ALERT_TAG_LIMIT = 50
ALERT_SOURCE_LIMIT = 100
ALERT_NOTE_LIMIT = 25000

def priority(severity_label)
  case severity_label
  when 'LOW'
    'P4'
  when 'MEDIUM'
    'P3'
  when 'HIGH'
    'P2'
  when 'CRITICAL'
    'P1'
  else
    'P5'
  end
end

def alert_alias(title, product)
  require 'base64'
  Base64.encode64("#{title}-#{product}")
end

def handler(event:, context:)
  log.info("Processing #{event['detail']['findings'].length} findings")

  event['detail']['findings'].each do |finding|
    next if finding['Severity']['Label'] == 'INFORMATIONAL'

    data = {
      account: finding['AwsAccountId'],
      region: ENV.fetch('AWS_REGION', 'ap-southeast-2'),
      product: finding['ProductArn'].split('/').last,
      message: finding['Title'].slice(0..ALERT_MESSAGE_LIMIT),
      alias: alert_alias(finding['Title'], finding['ProductArn'].split('/').last),
      description: finding['Description'].slice(0..ALERT_DESCRIPTION_LIMIT),
      type: finding['Types'].join(','),
      severity: finding['Severity']['Label'],
      priority: priority(finding['Severity']['Label']),
      details: finding['ProductFields'],
      tags: [
        "account:#{finding['AwsAccountId']}",
        "region:#{ENV.fetch('AWS_REGION', 'ap-southeast-2')}"
      ]
    }

    log.info(data)
  end
end

handler(event: JSON.parse(File.read('event.json')), context: {})
