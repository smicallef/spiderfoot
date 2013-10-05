// data should be an array of the items you want to plot
function sf_viz_bubble(targetId, plotData) { 
    var diameter = 700 - 30,
        limit = 5000,
        format = d3.format(",d"),
        color = d3.scale.category20c();

    var bubble = d3.layout.pack()
        .sort(null)
        .size([diameter, diameter])
        .padding(2);

    var svg = d3.select(targetId).append("svg")
        .attr("width", diameter)
        .attr("height", diameter)
        .attr("class", "bubble");

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
            {
                if (typeof(wordStr) != "undefined" && wordStr.length > 2) {
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
                showToolTip(" "+data[0][i]+"<br>"+data[1][i]+" ",d.x+d3.mouse(this)[0]+50,d.y+d3.mouse(this)[1],true);
            })
            .on("mousemove", function(d,i) {
                tooltipDivID.css({top:d.y+d3.mouse(this)[1],left:d.x+d3.mouse(this)[0]+50});
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
