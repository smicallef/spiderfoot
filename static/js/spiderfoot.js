//-------------------------------------------------------------------------------
// Name:         spiderfoot.js
// Purpose:      All the javascript code for the spiderfoot aspects of the UI.
//
// Author:      Steve Micallef <steve@binarypool.com>
//
// Created:     03/10/2012
// Copyright:   (c) Steve Micallef 2012
// Licence:     GPL
//-------------------------------------------------------------------------------

var sf = {}

sf.genericError = function(message) {
        alert("Failure: " + message);
}

sf.replace_sfurltag = function(data) {
    if (data.toLowerCase().indexOf("&lt;sfurl&gt;") >= 0) {
        data = data.replace(RegExp("&lt;sfurl&gt;(.*)&lt;/sfurl&gt;", "img"), "<a target=_new href='\$1'>\$1</a>");
    }
    if (data.toLowerCase().indexOf("<sfurl>") >= 0) {
        data = data.replace(RegExp("<sfurl>(.*)</sfurl>", "img"), "<a target=_new href='\$1'>\$1</a>");
    }
    return data;
}

sf.remove_sfurltag = function(data) {
    if (data.toLowerCase().indexOf("&lt;sfurl&gt;") >= 0) {
        data = data.toLowerCase().replace("&lt;sfurl&gt;", "").replace("&lt;/sfurl&gt;", "");
    }
    if (data.toLowerCase().indexOf("<sfurl>") >= 0) {
        data = data.toLowerCase().replace("<sfurl>", "").replace("</sfurl>", "");
    }
    return data;
}

sf.search = function(scan_id, value, type, postFunc) {
    sf.fetchData("/search", { id: scan_id, eventType: type, value: value }, postFunc);
}

sf.fetchData = function(url, postData, postFunc) {
    var req = $.ajax({
        type: "POST",
        url: url,
        data: postData,
        cache: false,
        dataType: "json"
    });

    req.done(postFunc);
    req.fail(function(hr, status) {
            sf.genericError("AJAX Error: " + status)
    });
}

/*
sf.simpleTable = function(id, data, cols, linkcol=null, linkstring=null, sortable=true, rowfunc=null) {
	var table = "<table id='" + id + "' ";
	table += "class='table table-bordered table-striped tablesorter'>";
	table += "<thead><tr>";
	for (var i = 0; i < cols.length; i++) {
		table += "<th>" + cols[i] + "</th>";
	}
	table += "</tr></thead><tbody>";

	for (var i = 1; i < data.length; i++) {
		table += "<tr>";
		for (var c = 0; c < data[i].length; c++) {
			if (c == linkcol) {
				if (linkstring.indexOf("%%col") > 0) {
				}
				table += "<td>" + <a class='link' onClick='" + linkstring + "'>";
				table += data[i][c] + "</a></td>"
			} else {
				table += "<td>" + data[i][c] + "</td>";
			}
		}
		table += "</tr>";
	}
	table += "</tbody></table>";

	return table;
}

*/

sf.updateTooltips = function() {
    $(document).ready(function () {
        if ($("[rel=tooltip]").length) {
            $('[rel=tooltip]').tooltip({container: 'body'});
        }
    });
}
