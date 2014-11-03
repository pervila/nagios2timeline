#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 
# See http://www.python.org/doc/2.5.4/lib/minimal-example.html for much more
# information on writing these tests.
#
"""This module tests a number of methods of Nagios2Timeline.py."""
import unittest
import Nagios2Timeline
__author__ = 'Pervilä <pervila@cs.helsinki.fi>'

class TestSeq(unittest.TestCase):
    def setUp(self):
        self.parser = Nagios2Timeline.optparser()
        (options, args) = self.parser.parse_args()
        self.writer = Nagios2Timeline.TimelineWriterXML('test-output.xml')
        self.reader = Nagios2Timeline.NagiosLogReader(self.writer, options)

        
    def test_getConfigIllegal(self):
        self.assertRaises(ValueError,
                          self.reader.get_config, 'NOT_EXIST')


    def test_getConfig(self):
        self.assertEqual(self.reader.get_config('verbose'), False)


    def test_setConfig(self):
        self.assertEqual(self.reader.set_config('verbose', True), True)


    def test_setConfigIllegal(self):
        self.assertRaises(ValueError,
                          self.reader.set_config, 'NOT_EXIST', None)


    def test_recordEventIllegal(self):
        self.assertRaises(ValueError,
                          self.reader.record_event, -5, 'localhost.localdomain'
                          'UP', 'ssh', None)


    def test_recordEvent(self):
        self.assertEqual(self.reader.record_event(
            '1256844672', 'localhost.localdomain', 
            'DOWN', 'http-proxy',
            'HTTP OK <html> - 1447 bytes in 0,058 seconds'), True)


    def test_recordEventInteger(self):
        self.assertEqual(self.reader.record_event(
            1256844672, 'localhost.localdomain', 
            'DOWN', 'http-proxy',
            'HTTP OK <html> - 1447 bytes in 0,058 seconds'), True)        
        

    def test_setOngoingEvents(self):
        events = [{'timestamp' : '1256844672',
                   'svc_desc' : 'globalcatTCPworldwide',
                   'plugin_output' :
                   'HTTP OK HTTP/1.1 200 OK - 10629 bytes in 5,503 seconds',
                   'state' : 'UNKNOWN',
                   'host_name' : 'melkinpaasi.cs.helsinki.fi'},
                  {'timestamp' : '22565544672',
                   'svc_desc' : 'TCPworldwide',
                   'plugin_output' :
                   'HTTP OK HTTP/1.1 200 OK - 10629 bytes in 5,503 seconds',
                   'state' : 'UNKNOWN',
                   'host_name' : 'melkinpaasi.cs.helsinki.fi'}]
        self.reader.set_ongoing_events(events)
        self.assert_('melkinpaasi.cs.helsinki.fi globalcatTCPworldwide' in
                     self.reader.ongoing_events)


    # Second event doesn't contain the state field.
    def test_setOngoingEventsIllegal(self):
        events = [{'timestamp' : '1256844672',
                   'svc_desc' : 'globalcatTCPworldwide',
                   'plugin_output' :
                   'HTTP OK HTTP/1.1 200 OK - 10629 bytes in 5,503 seconds',
                   'state' : 'UNKNOWN',
                   'host_name' : 'melkinpaasi.cs.helsinki.fi'},
                  {'timestamp' : '22565544672',
                   'svc_desc' : 'TCPworldwide',
                   'plugin_output' :
                   'HTTP OK HTTP/1.1 200 OK - 10629 bytes in 5,503 seconds',
                   'host_name' : 'melkinpaasi.cs.helsinki.fi'}]
        self.assertRaises(ValueError, self.reader.set_ongoing_events, events)
        

    def test_processIllegal(self):
        self.assertRaises(IOError, self.reader.process, '__NOT_EXISTING_FILE__')


    def test_process(self):
        self.reader.process('examples/nagios.log')
        self.assert_(len(self.reader.ongoing_events) == 0)
        

suite = unittest.TestLoader().loadTestsFromTestCase(TestSeq)
unittest.TextTestRunner(verbosity=2).run(suite)
