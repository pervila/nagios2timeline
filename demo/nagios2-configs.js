var tl;
function onLoad() {
  var eventSource = new Timeline.DefaultEventSource();
  var bandInfos = [
    Timeline.createBandInfo({
      eventSource:    eventSource,
      date:           "Oct 29 2009 12:00:00 GMT",     
      width:          "50%", 
      intervalUnit:   Timeline.DateTime.HOUR,
      intervalPixels: 100
    }),
    Timeline.createBandInfo({
      overview:       true,
      eventSource:    eventSource,
      date:           "Oct 29 2009 12:00:00 GMT",     
      width:          "30%", 
      intervalUnit:   Timeline.DateTime.DAY,
      intervalPixels: 100
    }),
    Timeline.createBandInfo({
      overview:       true,
      eventSource:    eventSource,
      date:           "Oct 29 2009 12:00:00 GMT",
      width:          "20%", 
      intervalUnit:   Timeline.DateTime.MONTH,
      intervalPixels: 100
    }),
  ];
  bandInfos[1].syncWith = 0;
  bandInfos[1].highlight = true;
  bandInfos[2].syncWith = 1;
  bandInfos[2].highlight = true;

  tl = Timeline.create(document.getElementById("nagios-timeline"), bandInfos);
  Timeline.loadXML('nagios2.xml', function(xml, url) { eventSource.loadXML(xml, url); });
}

var resizeTimerID = null;
function onResize() {
   if (resizeTimerID == null) {
       resizeTimerID = window.setTimeout(function() {
           resizeTimerID = null;
           tl.layout();
       }, 500);
   }
}
