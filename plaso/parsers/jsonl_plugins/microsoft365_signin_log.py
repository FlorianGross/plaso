# -*- coding: utf-8 -*-
"""JSON-L parser plugin for Microsoft 365 Sign-In Log files."""

from dfdatetime import time_elements as dfdatetime_time_elements
from plaso.containers import events
from plaso.parsers import jsonl_parser
from plaso.parsers.jsonl_plugins import interface


class Microsoft365SignInEventData(events.EventData):
  """Microsoft 365 Sign-In Log event data."""

  DATA_TYPE = 'microsoft365:signin:entry'

  def __init__(self):
    super().__init__(data_type=self.DATA_TYPE)
    self.created_datetime = None
    self.user_display_name = None
    self.user_principal_name = None
    self.user_id = None
    self.app_display_name = None
    self.app_id = None
    self.client_app_used = None
    self.user_agent = None
    self.ip_address = None
    self.correlation_id = None
    self.conditional_access_status = None
    self.result_status = None
    self.result_failure_reason = None
    self.resource_display_name = None
    self.authentication_requirement = None
    self.sign_in_event_types = None
    self.device_os = None
    self.device_browser = None
    self.city = None
    self.state = None
    self.country = None
    self.latitude = None
    self.longitude = None
    self.raw_data = None


class Microsoft365SignInJSONLPlugin(interface.JSONLPlugin):
  """JSON-L parser plugin for Microsoft 365 Sign-In logs."""

  NAME = 'microsoft365_signin_log'
  DATA_FORMAT = 'Microsoft 365 Sign-In Log'

  def _ParseRecord(self, parser_mediator, json_dict):
    created_datetime = json_dict.get('createdDateTime')
    dfdatetime_object = None
    if created_datetime:
      try:
        dfdatetime_object = dfdatetime_time_elements.TimeElements()
        dfdatetime_object.CopyFromStringISO8601(created_datetime)
      except Exception as e:
        parser_mediator.ProduceExtractionWarning(f'Invalid timestamp: {created_datetime}, error: {e}')

    event_data = Microsoft365SignInEventData()
    event_data.created_datetime = dfdatetime_object
    event_data.user_display_name = json_dict.get('userDisplayName')
    event_data.user_principal_name = json_dict.get('userPrincipalName')
    event_data.user_id = json_dict.get('userId')
    event_data.app_display_name = json_dict.get('appDisplayName')
    event_data.app_id = json_dict.get('appId')
    event_data.client_app_used = json_dict.get('clientAppUsed')
    event_data.user_agent = json_dict.get('userAgent')
    event_data.ip_address = json_dict.get('ipAddress')
    event_data.correlation_id = json_dict.get('correlationId')
    event_data.conditional_access_status = json_dict.get('conditionalAccessStatus')
    event_data.result_status = json_dict.get('status', {}).get('errorCode')
    event_data.result_failure_reason = json_dict.get('status', {}).get('failureReason')
    event_data.resource_display_name = json_dict.get('resourceDisplayName')
    event_data.authentication_requirement = json_dict.get('authenticationRequirement')
    event_data.sign_in_event_types = ','.join(json_dict.get('signInEventTypes', []))
    event_data.device_os = json_dict.get('deviceDetail', {}).get('operatingSystem')
    event_data.device_browser = json_dict.get('deviceDetail', {}).get('browser')
    event_data.city = json_dict.get('location', {}).get('city')
    event_data.state = json_dict.get('location', {}).get('state')
    event_data.country = json_dict.get('location', {}).get('countryOrRegion')
    event_data.latitude = json_dict.get('location', {}).get('geoCoordinates', {}).get('latitude')
    event_data.longitude = json_dict.get('location', {}).get('geoCoordinates', {}).get('longitude')
    event_data.raw_data = str(json_dict)
   
    parser_mediator.ProduceEventData(event_data)

  def CheckRequiredFormat(self, json_dict):
    return 'createdDateTime' in json_dict and 'userPrincipalName' in json_dict


jsonl_parser.JSONLParser.RegisterPlugin(Microsoft365SignInJSONLPlugin)
