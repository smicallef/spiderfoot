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

sf.fetchData = function(url, postData, postFunc, opts=null) {
    var req = $.ajax({
        type: "POST",
        url: url,
        data: postData,
        dataType: "json"
    });

    req.done(postFunc);
    req.fail(function(hr, status) {
            sf.genericError("AJAX Error: " + status)
    });
}

