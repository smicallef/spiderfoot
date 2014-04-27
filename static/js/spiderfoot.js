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

sf.updateTooltips = function() {
    $(document).ready(function () {
        if ($("[rel=tooltip]").length) {
            $("[rel=tooltip]").tooltip();
        }
    });
}
