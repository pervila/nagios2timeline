#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""Wrapper script that uses the Nagios2Timeline module

See the module's documentation for further information.

Copyright: GPL version 3 or later. See the file LICENSE for details."""
__author__ = 'Pervilä <pervila@cs.helsinki.fi>'
__version__ = 1


import Nagios2Timeline
import sys

EXIT = {'OK' : 0,
        'SYNTAX_ERROR' : 1}

def main():
    parser = Nagios2Timeline.optparser()
    # options will contain every specified option encountered
    # files will contain all remaining positional arguments
    (options, files) = parser.parse_args()

    if len(files) < 2:
        sys.stderr.write("Error: Missing input and output files.\n\n")
        parser.print_help()
        sys.exit(EXIT['SYNTAX_ERROR'])
    else:
        # Grab the last file for our output
        outputfile = files[-1]
        files = files[:-1]

    # Create XML or JSON output depending on command line parameters given
    # 'type' is not understood by NagiosLogReader.get_config()
    if options.format == 'JSON':
        writer = Nagios2Timeline.TimelineWriterJSON(outputfile, options.append)
    else:
        writer = Nagios2Timeline.TimelineWriterXML(outputfile, options.append)
        
    # Create reader object, passing it the options extracted from the
    # command line parameters.
    reader = Nagios2Timeline.NagiosLogReader(writer, options)
    
    # If we were set to append, parse all ongoing events from the event file
    # and populate NLR's internal data structure with them
    if options.append:
        reader.set_ongoing_events(writer.get_ongoing_events())

    # For each log file remaining as input, let NLR parse through the log and
    # pass events found to TLW for writing.
    for file in files:
        if options.verbose:
            print "Processing file %s" % file
        reader.process(file)

    # Finally, flush still ongoing events to the output.
    if options.verbose:
        print "Writing XML document %s" % outputfile
    reader.flush_events()

if __name__ == "__main__":
    main()
