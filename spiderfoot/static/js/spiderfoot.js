//-------------------------------------------------------------------------------
// Name:         spiderfoot.js
// Purpose:      All the javascript code for the spiderfoot aspects of the UI.
//
// Author:      Steve Micallef <steve@binarypool.com>
//
// Created:     03/10/2012
// Copyright:   (c) Steve Micallef 2012
// Licence:     MIT
//-------------------------------------------------------------------------------

// Toggler for theme
document.addEventListener("DOMContentLoaded", () => {
  const themeToggler = document.getElementById("theme-toggler");
  const head = document.getElementsByTagName("HEAD")[0];
  const togglerText = document.getElementById("toggler-text");
  let link = document.createElement("link");

  if (localStorage.getItem("mode") === "Light Mode") {
    togglerText.innerText = "Dark Mode";
    document.getElementById("theme-toggler").checked = true; // ensure theme toggle is set to dark
  } else { // initial mode ist null
    togglerText.innerText = "Light Mode";
    document.getElementById("theme-toggler").checked = false; // ensure theme toggle is set to light
  }


  themeToggler.addEventListener("click", () => {
    togglerText.innerText = "Light Mode";

    if (localStorage.getItem("theme") === "dark-theme") {
      localStorage.removeItem("theme");
      localStorage.setItem("mode", "Dark Mode");
      link.rel = "stylesheet";
      link.type = "text/css";
      link.href = "${docroot}/static/css/spiderfoot.css";

      head.appendChild(link);
      location.reload();
    } else {
      localStorage.setItem("theme", "dark-theme");
      localStorage.setItem("mode", "Light Mode");
      link.rel = "stylesheet";
      link.type = "text/css";
      link.href = "${docroot}/static/css/dark.css";

      head.appendChild(link);
      location.reload();
    }
  });
});

var sf = {};

sf.replace_sfurltag = function (data) {
  if (data.toLowerCase().indexOf("&lt;sfurl&gt;") >= 0) {
    data = data.replace(
      RegExp("&lt;sfurl&gt;(.*)&lt;/sfurl&gt;", "img"),
      "<a target=_new href='$1'>$1</a>"
    );
  }
  if (data.toLowerCase().indexOf("<sfurl>") >= 0) {
    data = data.replace(
      RegExp("<sfurl>(.*)</sfurl>", "img"),
      "<a target=_new href='$1'>$1</a>"
    );
  }
  return data;
};

sf.remove_sfurltag = function (data) {
  if (data.toLowerCase().indexOf("&lt;sfurl&gt;") >= 0) {
    data = data
      .toLowerCase()
      .replace("&lt;sfurl&gt;", "")
      .replace("&lt;/sfurl&gt;", "");
  }
  if (data.toLowerCase().indexOf("<sfurl>") >= 0) {
    data = data.toLowerCase().replace("<sfurl>", "").replace("</sfurl>", "");
  }
  return data;
};

sf.search = function (scan_id, value, type, postFunc) {
  sf.fetchData(
    "/search",
    { id: scan_id, eventType: type, value: value },
    postFunc
  );
};

sf.deleteScan = function(scan_id, callback) {
    var req = $.ajax({
      type: "GET",
      url: "/scandelete?id=" + scan_id
    });
    req.done(function() {
        alertify.success('<i class="glyphicon glyphicon-ok-circle"></i> <b>Scans Deleted</b><br/><br/>' + scan_id.replace(/,/g, "<br/>"));
        sf.log("Deleted scans: " + scan_id);
        callback();
    });
    req.fail(function (hr, textStatus, errorThrown) {
        alertify.error('<i class="glyphicon glyphicon-minus-sign"></i> <b>Error</b><br/></br>' + hr.responseText);
        sf.log("Error deleting scans: " + scan_id + ": " + hr.responseText);
    });
};

sf.stopScan = function(scan_id, callback) {
    var req = $.ajax({
      type: "GET",
      url: "/stopscan?id=" + scan_id
    });
    req.done(function() {
        alertify.success('<i class="glyphicon glyphicon-ok-circle"></i> <b>Scans Aborted</b><br/><br/>' + scan_id.replace(/,/g, "<br/>"));
        sf.log("Aborted scans: " + scan_id);
        callback();
    });
    req.fail(function (hr, textStatus, errorThrown) {
        alertify.error('<i class="glyphicon glyphicon-minus-sign"></i> <b>Error</b><br/><br/>' + hr.responseText);
        sf.log("Error stopping scans: " + scan_id + ": " + hr.responseText);
    });
};

sf.fetchData = function (url, postData, postFunc) {
  var req = $.ajax({
    type: "POST",
    url: url,
    data: postData,
    cache: false,
    dataType: "json",
  });

  req.done(postFunc);
  req.fail(function (hr, status) {
      alertify.error('<i class="glyphicon glyphicon-minus-sign"></i> <b>Error</b><br/>' + status);
  });
};

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

sf.updateTooltips = function () {
  $(document).ready(function () {
    if ($("[rel=tooltip]").length) {
      $("[rel=tooltip]").tooltip({ container: "body" });
    }
  });
};

sf.log = function (message) {
  if (typeof console == "object" && typeof console.log == "function") {
    var currentdate = new Date();
    var pad = function (n) {
      return ("0" + n).slice(-2);
    };
    var datetime =
      currentdate.getFullYear() +
      "-" +
      pad(currentdate.getMonth() + 1) +
      "-" +
      pad(currentdate.getDate()) +
      " " +
      pad(currentdate.getHours()) +
      ":" +
      pad(currentdate.getMinutes()) +
      ":" +
      pad(currentdate.getSeconds());
    console.log("[" + datetime + "] " + message);
  }
};
