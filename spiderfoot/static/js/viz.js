// Takes an object in the form of:
// { name: "blah", children: [ { name: "blah 2", children: [ ... ] } ] }
// and counts the number of objects without children
function sf_viz_countTailNodes(arg) {
    var data = arg;
    var count = 0;

    for (var i = 0; i < data.length; i++) {
        for (var p in data[i]) {
            if (p == "children" && data[i].children == null) {
                count++;
                continue;
            }
            if (p == "children" && data[i].children != null) {
                count += sf_viz_countTailNodes(data[i].children);
            }
        }
    }

    return count;
}

// As above but counts the total number of objects
function sf_viz_countTotalNodes(arg) {
    var data = arg;
    var count = 0;

    for (var i = 0; i < data.length; i++) {
        for (var p in data[i]) {
            if (p == "name") {
                count++;
                continue;
            }
            if (p == "children" && data[i].children != null) {
                count += sf_viz_countTotalNodes(data[i].children);
            }
        }
    }

    return count;
}

// As above but counts the highest number of levels
function sf_viz_countLevels(arg, levelsDeep, maxLevels) {
    var data = arg;
    var levels = levelsDeep;
    var max = maxLevels;

    for (var i = 0; i < data.length; i++) {
        for (var p in data[i]) {
            // We've hit a member with children..
            if (p == "children" && data[i].children != null) {
                levels++;
                arr = sf_viz_countLevels(data[i].children, levels, max);
                levels = arr[0];
                max = arr[1];
            }

            if (p == "children" && data[i].children == null) {
                if (levels > max) {
                    //alert("max = " + levels);
                    max = levels;
                }
            }
        }

        // Reset to the level we're at as we iterate through the next child.
        levels = levelsDeep;
    }

    return [ levels, max ];
}

function sf_viz_vbar(targetId, gdata) {
    var margin = {top: 20, right: 20, bottom: 220, left: 60},
        width = 1100 - margin.left - margin.right,
        height = 520 - margin.top - margin.bottom;

    var formatPercent = d3.format(".0%");

    var x = d3.scale.ordinal()
        .rangeRoundBands([0, width], .1);

    var y = d3.scale.linear()
        .range([height, 0]);

    var xAxis = d3.svg.axis()
        .scale(x)
        .orient("bottom");

    var yAxis = d3.svg.axis()
        .scale(y)
        .orient("left")

/*    var tip = d3.tip()
      .attr('class', 'd3-tip')
      .offset([-10, 0])
      .html(function(d) {
        return "<strong>counter Elements:</strong> <span style='color:red'>" + d.counter + "</span>";
      })
*/
    var svg = d3.select(targetId).append("svg")
        .attr("width", width + margin.left + margin.right)
        .attr("height", height + margin.top + margin.bottom)
      .append("g")
        .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

 //   svg.call(tip);

    data = new Array();
    for (i = 0; i < gdata.length; i++) {
        data[i] = sf_viz_vbar_type(gdata[i])
    }
    x.domain(data.map(function(d) { return d.name; }));
    y.domain([0, d3.max(data, function(d) { return d.pct*100; })]);

    svg.append("g")
        .attr("class", "x axis")
        .attr("transform", "translate(0," + height + ")")
        .call(xAxis)
        .selectAll("text")
            .style("text-anchor", "end")
            .attr("dx", "-.8em")
            .attr("dy", ".15em")
            .attr("transform", function(d) {
                return "rotate(-45)" 
            });

    svg.append("g")
        .attr("class", "y axis")
        .call(yAxis)
      .append("text")
        .attr("transform", "rotate(-90)")
        .attr("y", 6)
        .attr("dy", "-50px")
        .style("text-anchor", "end")
        .text("Percentage of Unique Elements");

    svg.selectAll(".bar")
        .data(data)
      .enter().append("rect")
        .attr("class", "bar")
        .attr("x", function(d) { return x(d.name); })
        .attr("width", x.rangeBand())
        .attr("y", function(d) { return y(d.pct*100); })
        .attr("height", function(d) { return height - y(d.pct*100); })
        .on('mousedown', function(d) { showToolTip(" ",0,0,false); d.link(d); } )
        .on("mouseover", function(d, i) {
            showToolTip(buildPopupMessage(d), d3.event.pageX+10, d3.event.pageY+10,true);
        })
        .on("mouseout", function() {
            showToolTip(" ",0,0,false);
        });


    function buildPopupMessage(data) {
        message = "<table>";
        message += "<tr><td><b>Type:</b></td><td>" + data.name + "</td></tr>";
        message += "<tr><td><b>Unique Elements:</b></td><td>" + data.counter + "</td></tr>";
        message += "<tr><td><b>Total Elements:</b></td><td>" + data.total+ "</td></tr>";
        message += "</table>";
        return message;
    }

    function showToolTip(pMessage,pX,pY,pShow) {
        if (typeof(tooltipDivID)=="undefined") {
            tooltipDivID =$('<div id="messageToolTipDiv" style="position:absolute;display:block;z-index:10000;border:2px solid black;background-color:rgba(0,0,0,0.8);margin:auto;padding:3px 5px 3px 5px;color:white;font-size:12px;font-family:arial;border-radius: 5px;vertical-align: middle;text-align: center;min-width:50px;overflow:auto;"></div>');
            $('body').append(tooltipDivID);
        }
        if (!pShow) { tooltipDivID.hide(); return;}
        tooltipDivID.html(pMessage);
        tooltipDivID.css({top:pY,left:pX});
        tooltipDivID.show();
    }
}

function sf_viz_vbar_type(d) {
      d.pct = +d.pct;
      return d;
}

function sf_viz_dendrogram(targetId, data) {
    var plotData = data['tree'];
    var dataMap = data['data'];
    var width = sf_viz_countLevels([plotData], 0, 0)[1] * 170;
    var height = sf_viz_countTailNodes([plotData]) * 20;

    if (width < 600) {
        width = 600;
    }
    if (height < 600) {
        height = 600;
    }  

    var cluster = d3.layout.cluster()
        .size([height, width - 160]);

    var diagonal = d3.svg.diagonal()
        .projection(function(d) { return [d.y, d.x]; });

    var svg = d3.select(targetId).append("svg")
        .attr("width", width)
        .attr("height", height)
        .append("g")
        .attr("transform", "translate(40,0)");

    var nodes = cluster.nodes(plotData),
        links = cluster.links(nodes);

    var link = svg.selectAll(".link")
        .data(links)
        .enter().append("path")
        .attr("class", "dend-link")
        .attr("d", diagonal);

    var node = svg.selectAll(".node")
        .data(nodes)
        .enter().append("g")
        .attr("class", "dend-node")
        .attr("transform", function(d) { return "translate(" + d.y + "," + d.x + ")"; })
        .on("mouseover", function(d, i) {
            d3.select(this).style("fill", "silver");
            showToolTip(buildPopupMessage(dataMap[d.name]), d3.event.pageX+10, d3.event.pageY+10,true);
        })
        .on("mouseout", function() {
            d3.select(this).style("fill", "black");
            showToolTip(" ",0,0,false);
        });

    node.append("circle")
        .attr("r", 4.5);

    node.append("text")
        .attr("dx", function(d) { 
            if (d.depth == 0) { 
                return 50;
            }

            return d.children ? -8 : 8; 
        })
        .attr("dy", 3)
        .style("text-anchor", function(d) { return d.children ? "end" : "start"; })
        .text(function(d) { 
            if (dataMap[d.name][1].length > 20) {
                return sf.remove_sfurltag(dataMap[d.name][1].substring(0, 20) + "...");
            } else {
                return sf.remove_sfurltag(dataMap[d.name][1]);
            }
        });

    d3.select(targetId).style("height", height + "px");

    function buildPopupMessage(data) {
        if (data[1].length > 200) {
            data[1] = data[1].substring(0, 200) + "...";
        }
        data[1] = data[1].replace("<", "&lt;").replace(">", "&gt;");
        message = "<table>";
        message += "<tr><td><b>Type:</b></td><td>" + data[10] + "</td></tr>";
        message += "<tr><td><b>Source Module:</b></td><td>" + data[3] + "</td></tr>";
        message += "<tr><td><b>Data:</b></td><td><pre>" + sf.remove_sfurltag(data[1])
        message += "</pre></td></tr>";
        message += "</table>";
        return message;
    }

    function showToolTip(pMessage,pX,pY,pShow) {
        if (typeof(tooltipDivID)=="undefined") {
            tooltipDivID =$('<div id="messageToolTipDiv" style="position:absolute;display:block;z-index:10000;border:2px solid black;background-color:rgba(0,0,0,0.8);margin:auto;padding:3px 5px 3px 5px;color:white;font-size:12px;font-family:arial;border-radius: 5px;vertical-align: middle;text-align: center;min-width:50px;overflow:auto;"></div>');
            $('body').append(tooltipDivID);
        }
        if (!pShow) { tooltipDivID.hide(); return;}
            tooltipDivID.html(pMessage);
            tooltipDivID.css({top:pY,left:pX});
            tooltipDivID.show();
    }
}


// Produces a bubble diagram enabling visually comparing size of
// data points.
// plotData should be an array of the items you want to plot
function sf_viz_bubble(targetId, plotData) { 
    var diameter = 900,
        format = d3.format(",d"),
        color = d3.scale.category20c();

    var bubble = d3.layout.pack()
        .sort(null)
        .size([diameter, diameter])
        .padding(1.5);

    var svg = d3.select(targetId).append("svg")
        .attr("width", diameter)
        .attr("height", diameter)

    var wordList = []; //each word one entry and contains the total count [ {cnt:30,title_list:[3,5,9],
    var wordCount = [];
    var wordMap = {};
    var wordIdList = [];
    var minVal = 10000;
    var maxVal = -100;
    var wordId = 0;
    var wordStr = "";

    for (var i = 0; i < plotData.length; i++) {
        wordStr = plotData[i];
        try {
            if (typeof(wordStr) != "undefined" && wordStr.length > 0) {
                wordStr = wordStr.toLowerCase();
                if (typeof(wordMap[wordStr]) == "undefined") {
                    wordList.push(wordStr);
                    wordCount.push(1);
                    wordMap[wordStr] = wordId;
                    wordIdList.push(wordId);
                    wordId++;
                } else {
                    wordCount[wordMap[wordStr]]++;
                }
            }   
        } catch (err) {
            alert("Error encountered parsing supplied words.")
        }
    }

    wordIdList.sort(function(x, y) { 
        return -wordCount[x] + wordCount[y] 
    });

    for (var wi = 0; wi < wordList.length; wi++) {
        if (minVal > wordCount[wi] ) minVal = wordCount[wi];
        if (maxVal < wordCount[wi] ) maxVal = wordCount[wi];
    }  

    var data = [
        wordList,
        wordCount
    ];

    var dobj=[];
    for (var di = 0; di < data[0].length; di++) {
        dobj.push({"key": di, "value": data[1][di]});
    }

    display_pack({children: dobj});

    function display_pack(root) {
        var node = svg.selectAll(".node")
            .data(bubble.nodes(root)
                .filter(function(d) { return !d.children; }))
            .enter().append("g")
            .attr("class", "node")
            .attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; })
            .style("fill", function(d) { return color(data[0][d.key]); })
            .on("mouseover", function(d,i) {
                d3.select(this).style("fill", "gold"); 
                showToolTip(" "+data[0][i]+"<br>"+data[1][i]+" ",d3.event.pageX+10, d3.event.pageY+10,true);
            })
            .on("mouseout", function() {
                d3.select(this).style("fill", function(d) { return color(data[0][d.key]); });
                showToolTip(" ",0,0,false);
            });

        node.append("circle")
            .attr("r", function(d) { return d.r; });

        node.append("text")
            .attr("dy", ".3em")
            .style("font", "10px sans-serif")
            .style("text-anchor", "middle")
            .style("fill","black")
            .text(function(d) { return data[0][d.key].substring(0, d.r / 3); });
    }

    function showToolTip(pMessage,pX,pY,pShow) {
        if (typeof(tooltipDivID)=="undefined") {
            tooltipDivID =$('<div id="messageToolTipDiv" style="position:absolute;display:block;z-index:10000;border:2px solid black;background-color:rgba(0,0,0,0.8);margin:auto;padding:3px 5px 3px 5px;color:white;font-size:12px;font-family:arial;border-radius: 5px;vertical-align: middle;text-align: center;min-width:50px;overflow:auto;"></div>');

            $('body').append(tooltipDivID);
        }

        if (!pShow) { tooltipDivID.hide(); return;}
            tooltipDivID.html(pMessage);
            tooltipDivID.css({top:pY,left:pX});
            tooltipDivID.show();
        }
}
