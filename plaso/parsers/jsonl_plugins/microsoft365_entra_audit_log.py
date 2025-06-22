# -*- coding: utf-8 -*-
"""JSON-L parser plugin for Microsoft 365 Audit Logs."""

from dfdatetime import time_elements as dfdatetime_time_elements
from dfdatetime import posix_time as dfdatetime_posix
from plaso.containers import events
from plaso.parsers import jsonl_parser
from plaso.parsers.jsonl_plugins import interface


class Microsoft365EntraAuditLogEventData(events.EventData):
    """Microsoft 365 Audit Log event data."""

    DATA_TYPE = 'microsoft365:entra_audit_log:entry'

    def __init__(self):
        super().__init__(data_type=self.DATA_TYPE)
        self.activity_display_name = None
        self.activity_datetime = None
        self.result = None
        self.result_reason = None
        self.operation_type = None
        self.service = None
        self.category = None
        self.correlation_id = None
        self.initiated_by_user_upn = None
        self.initiated_by_user_ip = None
        self.initiated_by_app = None
        self.additional_details = None


class Microsoft365EntraAuditLogPlugin(interface.JSONLPlugin):
    """JSON-L plugin for Microsoft 365 Audit Logs."""

    NAME = 'entra_audit_log'
    DATA_FORMAT = 'Microsoft 365 Entra Audit Log'

    def _ParseRecord(self, parser_mediator, json_dict):
        """Extracts events from a single Entra Audit Log entry."""

        event_data = Microsoft365EntraAuditLogEventData()

        event_data.activity_display_name = json_dict.get('activityDisplayName')
        event_data.activity_datetime = json_dict.get('activityDateTime')
        event_data.result = json_dict.get('result')
        event_data.result_reason = json_dict.get('resultReason')
        event_data.operation_type = json_dict.get('operationType')
        event_data.service = json_dict.get('loggedByService')
        event_data.category = json_dict.get('category')
        event_data.correlation_id = json_dict.get('correlationId')

        initiated_by = json_dict.get('initiatedBy', {})
        if isinstance(initiated_by.get('user'), dict):
            event_data.initiated_by_user_upn = initiated_by['user'].get('userPrincipalName')
            event_data.initiated_by_user_ip = initiated_by['user'].get('ipAddress')
        if isinstance(initiated_by.get('app'), dict):
            event_data.initiated_by_app = initiated_by['app'].get('displayName')

        details = json_dict.get('additionalDetails', [])
        if isinstance(details, list):
            event_data.additional_details = '; '.join(
                f"{d.get('key')}: {d.get('value')}" for d in details if 'key' in d and 'value' in d
            )

        activity_datetime = json_dict.get('activityDateTime')
        if activity_datetime:
            try:
                # Entferne 'Z' am Ende
                cleaned = activity_datetime.rstrip('Z')

                if '.' in cleaned:
                    # Mit Mikrosekunden
                    dt_part, us_part = cleaned.split('.')
                    us_part = us_part.ljust(6, '0')[:6]
                    microsecond = int(us_part)
                else:
                    dt_part = cleaned
                    microsecond = 0

                date_part, time_part = dt_part.split('T')
                year, month, day = map(int, date_part.split('-'))
                hour, minute, second = map(int, time_part.split(':'))

                time_elements_tuple = (
                    year, month, day, hour, minute, second, microsecond)

                event_data.activity_datetime = dfdatetime_time_elements.TimeElements(
                    time_elements_tuple=time_elements_tuple)
                event_data.datetime = f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}+00:00"
                
                parser_mediator.ProduceEventData(event_data)
            except Exception as e:
                parser_mediator.ProduceExtractionWarning(
                    f'Unable to parse activityDateTime: {activity_datetime} with error: {e}')
        
    
    def CheckRequiredFormat(self, json_dict):
        """Checks if a JSON record is a valid Entra audit log entry."""
        print("Test")
        if('activityDateTime' in json_dict and 'activityDisplayName' in json_dict):
            print("Detected Entra Audit log")
        return 'activityDateTime' in json_dict and 'activityDisplayName' in json_dict


jsonl_parser.JSONLParser.RegisterPlugin(Microsoft365EntraAuditLogPlugin)