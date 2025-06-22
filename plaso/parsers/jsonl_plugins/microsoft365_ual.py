# -*- coding: utf-8 -*-
"""JSON-L parser plugin for Microsoft 365 Unified Audit Log (UAL) files."""

import re

from dfdatetime import time_elements as dfdatetime_time_elements
from dfdatetime import posix_time as dfdatetime_posix
from plaso.containers import events
from plaso.parsers import jsonl_parser
from plaso.parsers.jsonl_plugins import interface
import json


class Microsoft365UALEventData(events.EventData):
  """Microsoft 365 Unified Audit Log (UAL) event data."""

  DATA_TYPE = 'microsoft365:ual:entry'

  def __init__(self):
    super(Microsoft365UALEventData, self).__init__(data_type=self.DATA_TYPE)
    self.record_type = None
    self.user_id = None
    self.user_key = None
    self.user_type = None
    self.operation = None
    self.workload = None
    self.client_ip = None
    self.object_id = None
    self.result_status = None
    self.creation_time = None
    self.datetime = None


class Microsoft365UALJSONLPlugin(interface.JSONLPlugin):
  """JSON-L parser plugin for Microsoft 365 UAL log files."""

  NAME = 'microsoft365_ual'
  DATA_FORMAT = 'Microsoft 365 Unified Audit Log (UAL)'
  _DOTNET_TIMESTAMP_REGEX = re.compile(r'/Date\((\d+)\)/')

  def _ParseRecord(self, parser_mediator, json_dict):
    audit_data = self._GetJSONValue(json_dict, 'AuditData') or {}
    creation_date = self._GetJSONValue(json_dict, 'CreationDate')
    
    date_time = None

    if creation_date:
      match = self._DOTNET_TIMESTAMP_REGEX.search(creation_date)
      if match:
        millis = int(match.group(1))
        # Umrechnung Millisekunden zu Sekunden und dann zu ISO8601
        timestamp = millis // 1000
        posix_dt = dfdatetime_posix.PosixTime(timestamp=timestamp)
        iso_string = posix_dt.CopyToDateTimeStringISO8601()
        # ISO-String bauen (UTC, da .NET-Zeitstempel in UTC sind)
        date_time = dfdatetime_time_elements.TimeElements()
        date_time.CopyFromStringISO8601(iso_string)
      else:
        print("Timestamp Error")
        parser_mediator.ProduceExtractionWarning(
            f'Unable to match timestamp in CreationDate: {creation_date}')

    event_data = Microsoft365UALEventData()
    event_data.record_type = self._GetJSONValue(json_dict, 'RecordType')
    event_data.user_id = self._GetJSONValue(audit_data, 'UserId')
    event_data.user_key = self._GetJSONValue(audit_data, 'UserKey')
    event_data.user_type = self._GetJSONValue(audit_data, 'UserType')
    event_data.operation = self._GetJSONValue(audit_data, 'Operation')
    event_data.workload = self._GetJSONValue(audit_data, 'Workload')
    event_data.client_ip = self._GetJSONValue(audit_data, 'ClientIP')
    event_data.object_id = self._GetJSONValue(audit_data, 'ObjectId')
    event_data.result_status = self._GetJSONValue(audit_data, 'ResultStatus')
    event_data.creation_time = date_time
    event_data.datetime = iso_string
    parser_mediator.ProduceEventData(event_data)
    

  def CheckRequiredFormat(self, json_dict):
    """Minimal format check for Microsoft 365 UAL."""
    creation_date = self._GetJSONValue(json_dict, 'CreationDate')
    audit_data = self._GetJSONValue(json_dict, 'AuditData')
    if(creation_date is not None):
      print("detected UAL")
    return creation_date is not None


jsonl_parser.JSONLParser.RegisterPlugin(Microsoft365UALJSONLPlugin)