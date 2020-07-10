    tabs = [ "use", "type", "module" ];
    activeTab = "use";

    function submitForm() {
        list = "";
        $("[id^="+activeTab+"_]").each(function() {
            if ($(this).is(":checked")) {
                list += $(this).attr('id') + ",";
            }
        });

        $("#"+activeTab+"list").val(list);
        for (i = 0; i < tabs.length; tabs++) {
            if (tabs[i] != activeTab) {
                $("#"+tabs[i]+"list").val("");
            }
        }
    }

    function switchTab(tabname) {
        $("#"+activeTab+"table").hide();
        $("#"+activeTab+"tab").removeClass("active");
        $("#"+tabname+"table").show();
        $("#"+tabname+"tab").addClass("active");
        activeTab = tabname;
        if (activeTab == "use") {
            $("#selectors").hide();
        } else {
            $("#selectors").show();
        }
    }

    function selectAll() {
        $("[id^="+activeTab+"_]").prop("checked", true);
    }

    function deselectAll() {
        $("[id^="+activeTab+"_]").prop("checked", false);
    }

  $('#scantarget').popover({ 'html': true, 'animation': true, 'trigger': 'focus'});
  if ("${selectedmods}" != "") {
          switchTab("module");
  
          $("input[id^=module_]").each(function(id, obj) { 
              if ("${selectedmods}".indexOf(obj.id.replace("module_", "")) >= 0) {
                  $("#" + obj.id).attr("checked", true);
              } else {
                  $("#" + obj.id).attr("checked", false);
              }
          });
  }

