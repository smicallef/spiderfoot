// llamaFoot front end helpers: live target detection, AI provider selector, AI scan summary.
// All server text is inserted with .text() or escaped, never as HTML.
(function () {
    var root = (typeof docroot !== "undefined") ? docroot : "";

    function esc(s) {
        return $("<div>").text(s == null ? "" : String(s)).html();
    }

    function tipHtml(text) {
        return esc(text).replace(/\n/g, "<br>");
    }

    function postJson(path, data) {
        return $.ajax({
            url: root + path,
            type: "POST",
            data: data,
            dataType: "json",
            headers: { "X-Requested-With": "XMLHttpRequest" }
        });
    }

    // ---- Live target detection -------------------------------------------------
    window.llamafootDetect = function (inputSel, badgeSel) {
        var timer = null;
        var $in = $(inputSel), $badge = $(badgeSel);

        function render(res) {
            $badge.empty();
            if (!res || !res.ok) {
                if ($in.val().trim() !== "") {
                    $badge.append($("<span class='label label-danger'>").text("Not recognised"));
                    $badge.append($("<span class='text-muted'>").text(" " + ((res && res.error) || "")));
                }
                return;
            }
            var cls = { high: "label-success", medium: "label-info", low: "label-warning" }[res.confidence] || "label-default";
            $badge.append($("<span class='label'>").addClass(cls).text("Detected: " + res.label));
            if (res.value && res.value !== $in.val().trim()) {
                $badge.append($("<span class='text-muted'>").text(" → " + res.value));
            }
            if (res.notes && res.notes.length) {
                $badge.append($("<div class='text-muted' style='font-size:11px'>").text(res.notes.join(" ")));
            }
            if (res.alternatives && res.alternatives.length) {
                var alts = res.alternatives.map(function (a) { return a.label + " (" + a.value + ")"; }).join(", ");
                $badge.append($("<div class='text-muted' style='font-size:11px'>").text("Could also be: " + alts));
            }
        }

        function run() {
            var v = $in.val();
            if (!v || !v.trim()) { $badge.empty(); return; }
            $.getJSON(root + "/detecttarget", { target: v }).done(render);
        }

        $in.on("input", function () { clearTimeout(timer); timer = setTimeout(run, 250); });
        run();
    };

    // ---- AI provider selector --------------------------------------------------
    window.llamafootAiSelector = function (rootSel) {
        var $root = $(rootSel);
        var state = { providers: [], selected: null, writable: true };

        $root.html(
            "<div class='form-inline' style='margin-bottom:6px'>" +
            "<label for='ai-provider'>AI engine&nbsp;</label>" +
            "<select id='ai-provider' class='form-control input-sm' style='min-width:220px'></select> " +
            "<span id='ai-badge' class='label label-success' style='margin-left:6px'></span> " +
            "<i id='ai-help' class='glyphicon glyphicon-question-sign' style='margin-left:6px;cursor:help'></i>" +
            "</div>" +
            "<div class='form-inline' id='ai-config' style='margin-bottom:6px'>" +
            "<label for='ai-model'>Model&nbsp;</label>" +
            "<input id='ai-model' list='ai-models' class='form-control input-sm' style='min-width:220px' autocomplete='off'>" +
            "<datalist id='ai-models'></datalist> " +
            "<span id='ai-keywrap'><label for='ai-key' style='margin-left:8px'>API key&nbsp;</label>" +
            "<input id='ai-key' type='password' class='form-control input-sm' autocomplete='off' style='min-width:220px'></span> " +
            "<button type='button' id='ai-save' class='btn btn-default btn-sm'>Save</button> " +
            "<button type='button' id='ai-test' class='btn btn-default btn-sm'>Test</button> " +
            "<span id='ai-status' class='text-muted' style='margin-left:8px'></span>" +
            "</div>" +
            "<div class='text-muted' style='font-size:11px'>Optional. AI is used to write scan summaries after a scan. " +
            "Choose a local model to keep results on your own server.</div>"
        );

        function current() {
            return state.providers.filter(function (p) { return p.id === $("#ai-provider").val(); })[0];
        }

        function status(msg, ok) {
            $("#ai-status").removeClass("text-success text-danger text-muted")
                .addClass(ok === true ? "text-success" : ok === false ? "text-danger" : "text-muted").text(msg || "");
        }

        function refreshModels() {
            var p = current();
            $("#ai-models").empty();
            if (!p || (p.needs_key && !p.key_configured && !$("#ai-key").val())) { return; }
            $.getJSON(root + "/llmmodels", { provider: p.id }).done(function (res) {
                (res.models || []).forEach(function (m) { $("#ai-models").append($("<option>").attr("value", m)); });
                if (res.error) { status(res.error, false); }
            });
        }

        function showProvider() {
            var p = current();
            if (!p) { return; }
            $("#ai-badge").text(p.badge).removeClass("label-success label-info label-warning")
                .addClass(p.local ? "label-success" : "label-info");
            $("#ai-help").attr("data-original-title", "").tooltip("destroy");
            $("#ai-help").tooltip({ container: "body", html: true, placement: "right", title: tipHtml(p.tooltip) });
            $("#ai-model").val(p.model || "");
            $("#ai-keywrap").toggle(!!p.needs_key);
            $("#ai-key").val("").attr("placeholder", p.key_configured ? "saved (leave blank to keep)" : (p.key_env || ""));
            status(p.needs_key && !p.key_configured ? "Needs an API key. Hover the ? for setup steps." : "");
            if (!state.writable) { $("#ai-save,#ai-key,#ai-model").prop("disabled", true); status("Settings are locked by the server administrator."); }
            refreshModels();
        }

        $.getJSON(root + "/llmproviders").done(function (res) {
            state = res;
            var $sel = $("#ai-provider");
            res.providers.forEach(function (p) {
                $sel.append($("<option>").attr("value", p.id).text(p.name + "  [" + p.badge + "]"));
            });
            $sel.prepend($("<option>").attr("value", "").text("None (no AI summaries)"));
            $sel.val(res.selected || "");
            if (!res.selected) { $("#ai-config,#ai-badge,#ai-help").hide(); } else { showProvider(); }
        });

        $root.on("change", "#ai-provider", function () {
            var on = !!$("#ai-provider").val();
            $("#ai-config,#ai-badge,#ai-help").toggle(on);
            if (on) { showProvider(); } else { status(""); }
        });

        $root.on("click", "#ai-save", function () {
            var p = current(); if (!p) { return; }
            var data = { provider: p.id, model: $("#ai-model").val() };
            if ($("#ai-key").val()) { data.apikey = $("#ai-key").val(); }
            postJson("/llmsave", data).done(function (res) {
                if (res.ok) {
                    if (data.apikey) { p.key_configured = true; $("#ai-key").val("").attr("placeholder", "saved (leave blank to keep)"); }
                    p.model = data.model;
                    status("Saved.", true); refreshModels();
                } else { status(res.error, false); }
            }).fail(function () { status("Could not save.", false); });
        });

        $root.on("click", "#ai-test", function () {
            var p = current(); if (!p) { return; }
            status("Testing...");
            var run = function () {
                postJson("/llmtest", { provider: p.id, model: $("#ai-model").val() }).done(function (res) {
                    status(res.ok ? "Working." : res.error, !!res.ok);
                }).fail(function () { status("Test failed.", false); });
            };
            if ($("#ai-key").val() || $("#ai-model").val() !== p.model) { $("#ai-save").trigger("click"); setTimeout(run, 600); } else { run(); }
        });
    };

    // ---- AI scan summary -------------------------------------------------------
    window.llamafootAiSummary = function (scanId) {
        var id = "ai-summary-modal";
        $("#" + id).remove();
        var $m = $(
            "<div class='modal fade' id='" + id + "' tabindex='-1'><div class='modal-dialog modal-lg'><div class='modal-content'>" +
            "<div class='modal-header'><button type='button' class='close' data-dismiss='modal'>&times;</button>" +
            "<h4 class='modal-title'>AI summary <small id='ai-sum-by'></small></h4></div>" +
            "<div class='modal-body'><div id='ai-sum-select'></div><hr>" +
            "<pre id='ai-sum-text' style='white-space:pre-wrap;word-wrap:break-word;background:none;border:0;font-family:inherit;font-size:13px'></pre></div>" +
            "<div class='modal-footer'><span class='text-muted pull-left' style='font-size:11px'>AI can be wrong. Check findings against the raw results.</span>" +
            "<button type='button' class='btn btn-primary' id='ai-sum-run'>Write summary</button> " +
            "<button type='button' class='btn btn-default' data-dismiss='modal'>Close</button></div>" +
            "</div></div></div>"
        );
        $("body").append($m);
        window.llamafootAiSelector("#ai-sum-select");
        $m.modal("show");

        $m.on("click", "#ai-sum-run", function () {
            var $btn = $(this).prop("disabled", true);
            $("#ai-sum-text").text("Reading the scan results and asking the model. Local models can take a minute or more...");
            postJson("/aisummary", { id: scanId, provider: $("#ai-provider").val(), model: $("#ai-model").val() })
                .done(function (res) {
                    if (res.ok) {
                        $("#ai-sum-text").text(res.summary);
                        $("#ai-sum-by").text("by " + res.model + " via " + res.provider);
                    } else { $("#ai-sum-text").text(res.error || "Something went wrong."); }
                })
                .fail(function () { $("#ai-sum-text").text("The request failed."); })
                .always(function () { $btn.prop("disabled", false); });
        });
    };
})();
