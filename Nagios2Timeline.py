#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""Converts Nagios log files into event source files readable by the
Timeline widget.

This version currently only provides XML output, JSON is under development.

The following two references provide additional information.
  [1] Marc Powell, nagios.log format:
  http://www.mail-archive.com/nagios-users@lists.sourceforge.net/msg15278.html

  [2] Timeline wiki, Event Attributes and Data Formats:
  http://code.google.com/p/simile-widgets/wiki/Timeline_EventSources

Copyright: GPL version 3 or later. See the file LICENSE for details."""
from __future__ import with_statement
import re
import sys
import time
import xml.dom.minidom
from os.path import exists as File_exists
from optparse import OptionParser, OptionGroup, Values
__version__ = '1'
__author__ =  'Pervilä <pervila@cs.helsinki.fi>'

def optparser():
    """Create an OptionParser compatible with Nmap2Timeline objects."""
    usage = "usage: %prog [options] logfile1 logfile2 ... outputfile"
    parser = OptionParser(usage=usage)
    group = OptionGroup(parser, "Omit host or service states",
                        "Each option silently discards events of that type.")
    group.add_option("-s", "--omit-services",
                      action="store_false", dest="services",
                      help="omit service events")
    group.add_option("-o", "--omit-hosts",
                      action="store_false", dest="hosts",
                      help="omit host events")
    group.add_option("-w", "--omit-warning",
                      action="store_false", dest="WARNING",
                      help="omit services in a warning state")
    group.add_option("-d", "--omit-down",
                      action="store_false", dest="DOWN",
                      help="omit hosts that are down ")
    group.add_option("-r", "--omit-unreachable",
                      action="store_false", dest="UNREACHABLE",
                      help="omit unreachability notifications")
    group.add_option("-c", "--omit-critical",
                      action="store_false", dest="CRITICAL",
                      help="omit services in a critical state")
    group.add_option("-u", "--omit-unknown",
                      action="store_false", dest="UNKNOWN",
                      help="omit services in an unknown state")
    parser.add_option_group(group)
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose",
                      help="verbose output")
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose",
                      help="operate as quietly as possible")
    parser.add_option("-f", "--format", metavar="FORMAT", 
                      action="store", dest="format", type="string",
                      help="output FORMAT: XML or JSON [default: %default]")
    parser.add_option("-a", "--append",
                      action="store_true", dest="append",
                      help="append to output file")
    parser.set_defaults(services=False, hosts=False, WARNING=False, DOWN=False,
                        UNREACHABLE=False, CRITICAL=False, UNKNOWN=False,
                        verbose=False, format='XML', append=False)
    return parser


class NagiosLogReader(object):
    """NagiosLogReader encapsulates Nagios events and calls a TimelineWriter
    for output.

    We keep a running total of events detected and assign each event its own
    unique identifier. Events are forgotten as soon as they can be output,
    so the memory requirement is directly relational to the number of objects
    concurrently in a nonworking state."""

    # The following error states are possible for hosts and services
    HOST_NONOK_STATES = [ 'DOWN', 'UNREACHABLE' ]
    SVC_NONOK_STATES = [ 'WARNING', 'CRITICAL', 'UNKNOWN' ]

    # These two regexps match service and host alerts, respectively
    #
    # (Note that we don't actually use the semicolon from the HOST line, it is
    # grouped only to match the positions below.)
    #
    # TODO: Unicode flags for re.compile?
    #
    # [1256805642] HOST ALERT: svm-5.cs.helsinki.fi;DOWN; \
    # SOFT;2;CRITICAL - Host Unreachable (128.214.11.45)
    RE_HOST = re.compile(r'\[(\d+)\] HOST ALERT: ([^;]+)(;)([^;]+);' + \
                         r'[^;]+;[^;]+;(.+)')

    # [1256805672] SERVICE ALERT: svm-5.cs.helsinki.fi;SSH; \
    # CRITICAL;HARD;1;No route to host
    RE_SVC = re.compile(r'\[(\d+)\] SERVICE ALERT: ([^;]+);([^;]+);' + \
                        r'([^;]+);[^;]+;[^;]+;(.+)')

    # At which positions are the interesting values?
    # I could use group renaming, but it would make the regexp even uglier...
    RE_INDEX_TIME = 1
    RE_INDEX_HOST = 2
    RE_INDEX_SVC = 3
    RE_INDEX_STATE = 4
    RE_INDEX_PLUG = 5
    
    def __init__(self, TimelineWriter, options):
        """Use TimelineWriter for output, set defaults, then configs given.

        options must be an instance of optparse.Values

        Raises ValueError if any of the set_config():s does so."""
        self.writer = TimelineWriter
        if isinstance(options, Values):
            self.options = options
        else:
            raise ValueError, "options must be an instance of optparse.Values"
        self.events_seen = 0    # how many events we have processed
        self.last_timestamp = 0 # most recent event seen
        # Record all objects in non-ok states in this dictionary.
        self.ongoing_events = {}
                

    def get_config(self, setting):
        """Get value of configuration setting.

        Raises ValueError if setting is unknown."""
        if not hasattr(self.options, setting):
            raise ValueError, "Unknown configuration setting %s" % setting
        # subtly different from self.options.setting
        return getattr(self.options, setting)


    def set_config(self, setting, value):
        """Set configuration setting to value.

        Raises ValueError if setting is unknown or an illegal value was
        given."""
        if not hasattr(self.options, setting):
            raise ValueError, "Unknown configuration setting %s=%s" % \
                  (setting, value)
        # subtly different from self.options.setting = value
        setattr(self.options, setting, value)
        return value


    def record_event(self, timestamp, host_name, state, svc_desc="",
                     plugin_output=""):
        """Record host or service event, output if the state was a recovery.

        Services are recognised by a nonempty svc_desc parameter.

        Raises ValueError if the parameters given are invalid.
        Raises Warnings if the event ordering seems broken.

        Each event MUST contain the following attributes:
            host_name
            timestamp_start : when malfunction started
            state : type of malfunction
            title : host_name [+ svc_desc] if available
        Each event MAY contain the following attributes:
            timestamp_end : when malfunction ceased
            svc_desc : description of service, if relevant
            plugin_start : output of plugin at start
            plugin_end: output of plugin at end"""
        identifier = host_name
        timestamp = int(timestamp)
        if self.last_timestamp < timestamp:
            self.last_timestamp = timestamp
        if svc_desc:
              identifier = identifier + ' ' + svc_desc
        if (state == "OK" or state == "UP"):
            # Look for a match from our tab of ongoing events. If found,
            # let our TimelineWriter output the event and remove the entry
            # from our tab.
            if identifier in self.ongoing_events:
                event = self.ongoing_events[identifier] # just a shortcut
                event['timestamp_end'] = timestamp
                if plugin_output:
                    event['plugin_end'] = plugin_output
                self.writer.output(event)
                del self.ongoing_events[identifier]
            else:
                raise Warning, "Recovery for previously unseen event."
        elif state in self.HOST_NONOK_STATES + self.SVC_NONOK_STATES:
            # This object has entered a nonworking state: create a new record
            # and add it to our tab of ongoing_events.
            if identifier not in self.ongoing_events:
                event = {
                    'timestamp_start' : timestamp,
                    'host_name' : host_name,
                    'state' : state,
                    'title' : identifier
                    }
                if svc_desc:
                    event['svc_desc'] = svc_desc
                if plugin_output:
                    event['plugin_start'] = plugin_output
                self.ongoing_events[identifier] = event
        else:
            raise ValueError, "Unknown host state %s" % state
        # Record successful.
        return True


    def set_ongoing_events(self, events):
        """Populate our ongoing events from the list of events given.

        The list given to this method is most commonly returned by a
        TimelineWriter's get_ongoing_events method.

        If used directly, each element in events must define key, value pairs
        suitable as record_event()'s arguments."""
        for event in events:
            try:
                self.record_event(event['timestamp'], event['host_name'],
                                  event['state'], event.get('svc_desc'),
                                  event.get('plugin_output'))
            except KeyError:
                raise ValueError, \
                    "Malformed event in list of events given as parameter."
            

    def process(self, filename):
        """Search through filename for host and/or service events.

        Each event given an unique integer identifier. Objects which have
        switched to a non-working state are recorded as ongoing events.
        Whenever an object returns to a working state, it is removed
        from ongoing and passed to the TimelineWriter object for output."""
        with open(filename) as f:
            linenum = 0
            for line in f:
                linenum += 1
                match = None
                # If we are not set to omit services, try to match line
                if not self.options.services:
                    match = self.RE_HOST.match(line)
                # No match and we are not set to omit services? Try again:
                if not (match or self.options.hosts):
                    match = self.RE_SVC.match(line)
                if match:
                    # We are set to process the state if it matches one of the
                    # NON-OK states and we were NOT configured to omit that
                    # state. (OK and UP states are always recorded)
                    state = match.group(self.RE_INDEX_STATE)
                    if (state == 'OK' or state == 'UP') or \
                       ((state in \
                         self.HOST_NONOK_STATES + self.SVC_NONOK_STATES) and \
                        not self.get_config(state)):
                        # found a matching event!
                        self.events_seen += 1
                        # If this was actually a host, cleanse the placeholder.
                        svc = match.group(self.RE_INDEX_SVC)
                        if svc == ';':
                            svc = None
                        try:
                            self.record_event(
                                match.group(self.RE_INDEX_TIME),
                                match.group(self.RE_INDEX_HOST),
                                state,
                                svc,
                                match.group(self.RE_INDEX_PLUG))
                        except Warning:
                            if self.options.verbose:
                                sys.stderr.write(
"Warning: recovery for previously unseen event. In file %s:\n    %s" % \
(filename, line))
                        except ValueError:
                            sys.stderr.write(
"Error: Malformed line %d of file %s (bypassing)\n" % (linenum, filename))


    def flush_events(self):
        """Flush any remaining ongoing events to the TimelineWriter.

        Note that the events may lack an ending timestamp, if no such
        timestamp was not found from the logs. In such cases, we assume
        that flush_events() is the last call to this reader and fill in
        the last seen timestamp + 1 for any ongoing events.

        TimelineWriter should record the last seen timestamp when closing its
        output file. When appending, TimelineWriter should look for events with
        timestamp + 1 and return them as still ongoing."""
        for event in self.ongoing_events.itervalues():
            event['timestamp_end'] = self.last_timestamp + 1
            self.writer.output(event)
        self.writer.flush_file(self.last_timestamp)
        # Garbage collect and reset
        self.ongoing_events = {}



class TimelineWriter(object):
    """Base class for writing event source files compatible with Timeline.

    Contains event attribute constraints common for all source file types."""
    # Output formats for format_time(), below
    TFORMAT_TIMELINE = 0
    TFORMAT_RFC2822 = 1

    
    def __init__(self, filename, append=False):
        """Empty interface, implemented by derived classes."""
        pass


    def verify(self, event):
        """Verify that the event passes Timeline's general constraints.

        Event should be passed as a dictionary.

        Raises ValueError if constraints are not met."""


    def format_time(self, timestamp, form=TFORMAT_TIMELINE):
        """Formats timestamp according to multiple formats.

        The parameter form may be one of
            TFORMAT_TIMELINE : Timeline's default representation
                (default here, also)
            TFORMAT_RFC2822 : RFC2822 Internet email standard."""
        if form == self.TFORMAT_TIMELINE:
            # Timeline's default format, e.g.
            # "May 10 1961 00:00:00 GMT-0600"
            utc = time.gmtime(int(timestamp))
            return time.strftime("%b %d %Y %H:%M:%S GMT%z", utc)
        elif form == self.TFORMAT_RFC2822:
            # RFC 2822 (Internet email std) timestamp, e.g.
            # "Thu, 21 Dec 2000 16:01:07 +0200"
            # 
            # TODO: Fix this
            local = time.localtime(int(timestamp))
            return time.strftime("%a, %d %b %Y %H:%M:%S %z", local)


    def output(self, event):
        """Write the given event to the standard output.

        Derived classes should implement their own versions which output the
        events to a given file.

        Raises ValueError if the event does not meet Timeline's attribute
        constraints."""
        self.verify(event)
        print "Event output:"
        for (k,v) in event.iteritems():
            if k.startswith('timestamp_'):
                v = self.format_time(v)
            print "    %s : %s" % (k,v)            


    def get_ongoing_events(self):
        """Return all ongoing events as a dictionary.

        This method must be implemented by each derived class. The
        implementation is specific to the event source format."""
        pass


    def flush_file(self, last_timestamp=0):
        """Close the output file, potentially writing footers and such.

        This method must be implemented by each derived class. The
        implementation is specific to the event source format."""
        pass



class TimelineWriterXML(TimelineWriter):
    """Extends XML-specific event attribute constraints."""

    def __init__(self, filename, append=False):
        """Create or append to XML document filename.

        If append is set to True, we will try to read the last-seen attribute
        of the XML document.

        TODO: wiki-url, wiki-section."""
        self.dom = None
        self.filename = filename
        if append:
            self.dom = xml.dom.minidom.parse(filename)
            self.root = self.dom.documentElement
            try: 
                self.last_timestamp = \
                    int(self.root.getAttribute('last_timestamp'))
            except ValueError:
                raise ValueError, "XML document does not contain " + \
                      "last_timestamp attribute and append mode requested."
        else:
            if File_exists(filename):
                raise IOError, \
                    "File %s exists and not instructed to append." % filename
            self.dom = xml.dom.minidom.Document()
            self.root = self.dom.createElement('data')
            self.dom.appendChild(self.root)


    def get_ongoing_events(self):
        """Parse XML doc for duration events with ending dates larger than the
        last_timestamp attribute of the doc.

        Thus, duration events may span multiple module executions."""
        ongoing_events = {}
        for node in self.root.childNodes:
            if node.localName == 'event':
                if node.getAttribute('end') == self.last_timestamp + 1:
                    event['timestamp_start'] = node.getAttribute('start')
                    event['title'] = node.getAttribute('title')
                    # TODO: plugin_start and plugin_end
        return ongoing_events


    def output(self, event):
        """Write the given event to the output file.

        The output is potentially rewritten to conform with XML requirements.

        Raises ValueError if not all required attributes are set."""
        # Straight-forwardly record found event data as a new XML element's
        # attributes. Conditionally existing data must be handled more
        # carefully. See NagiosLogReader.record_event for possible attributes.
        new_element = self.dom.createElement('event')
        new_element.setAttribute('start',
                                 self.format_time(event['timestamp_start']))
        new_element.setAttribute('end',
                                 self.format_time(event['timestamp_end']))
        new_element.setAttribute('durationEvent', 'true')
        # The title contains 'host_name' or 'host_name svc_desc'
        new_element.setAttribute('title', event['title'])
        content = ''
        for i in ['plugin_start', 'plugin_end']:
            if i in event:
                content += "%s : %s\n" % (i, event[i].strip())
        new_element.appendChild(self.dom.createTextNode(content))
        self.root.appendChild(new_element)
        

    def flush_file(self, last_timestamp):
        """Writes DOM tree to XML document and closes it."""
        self.root.setAttribute('last_timestamp', str(last_timestamp))
        with open(self.filename, 'w') as f:
            # No indent for first node, then two spaces for each level
            self.dom.writexml(f, '', '  ', '\n')
        self.dom.unlink()


class TimelineWriterJSON(TimelineWriter):
    """Extends JSON-specific event attribute constraints.

    Under development."""
    pass


def demo():
    if 'Nagios2Timeline' not in dir():
        import Nagios2Timeline
    else:
        reload(Nagios2Timeline)
    writer = TimelineWriterXML('nagios-example2.xml')
    reader = NagiosLogReader(writer)
    reader.process('example.log')
    reader.flush_events()
