# To run the tests, start sf web interface:
#   python3 ./sf.py -l 127.0.0.1:5001
# then run robot (override the BROWSER variable if necessary):
#   robot --variable BROWSER:Firefox --outputdir results scan.robot

*** Settings ***
Library         SeleniumLibrary
Test Teardown   Close All Browsers

*** Variables ***
${BROWSER}        Firefox
${HOST}           127.0.0.1
${PORT}           5001
${URL}            http://${HOST}:${PORT}

*** Keywords ***
Create a module scan
    [Arguments]  ${scan_name}  ${scan_target}  ${module_name}
    Open browser            ${URL}/newscan  ${BROWSER}
    Press Keys              name:scanname                   ${scan_name}
    Press Keys              name:scantarget                 ${scan_target}
    Click Element           id:moduletab
    Click Element           id:btn-deselect-all
    Scroll To Element       id:module_${module_name}
    Set Focus To Element    id:module_${module_name}
    Click Element           id:module_${module_name}
    Scroll To Element       id:btn-run-scan
    Click Element           id:btn-run-scan

Create a use case scan
    [Arguments]  ${scan_name}  ${scan_target}  ${use_case}
    Open browser            ${URL}/newscan  ${BROWSER}
    Press Keys              name:scanname                   ${scan_name}
    Press Keys              name:scantarget                 ${scan_target}
    Click Element           id:usecase_${use_case}
    Scroll To Element       id:btn-run-scan
    Click Element           id:btn-run-scan
 
Scan info page should render tabs
    Element Should Be Visible            id:btn-status
    Element Should Be Visible            id:btn-browse
    Element Should Be Visible            id:btn-correlations
    Element Should Be Visible            id:btn-graph
    Element Should Be Visible            id:btn-info
    Element Should Be Visible            id:btn-log

Scan info Summary tab should render
    Scan info page should render tabs
    Element Should Be Visible            id:vbarsummary

Scan info Browse tab should render
    Scan info page should render tabs
    Element Should Be Visible            id:btn-refresh
    Element Should Be Visible            id:btn-export
    Element Should Be Visible            id:searchvalue
    Element Should Be Visible            id:searchbutton

Scan info Correlations tab should render
    Scan info page should render tabs
    Element Should Be Visible            id:scansummary-content

Scan info Graph tab should render
    Scan info page should render tabs
    Element Should Be Visible            id:graph-container

Scan info Settings tab should render
    Scan info page should render tabs
    Page Should Contain                  Meta Information
    Page Should Contain                  Global Settings

Scan info Log tab should render
    Scan info page should render tabs
    Element Should Be Visible            id:btn-refresh
    Element Should Be Visible            id:btn-download-logs

Scan list page should render
    Element Should Be Visible            id:scanlist
    Element Should Be Visible            id:btn-rerun
    Element Should Be Visible            id:btn-stop
    Element Should Be Visible            id:btn-refresh
    Element Should Be Visible            id:btn-export
    Element Should Be Visible            id:btn-delete

Settings page should render
    Element Should Be Visible            id:savesettingsform
    Element Should Be Visible            id:btn-save-changes
    Element Should Be Visible            id:btn-import-config
    Element Should Be Visible            id:btn-opt-export
    Element Should Be Visible            id:btn-reset-settings

New scan page should render
    Element Should Be Visible            id:scanname
    Element Should Be Visible            id:scantarget
    Element Should Be Visible            id:usetab
    Element Should Be Visible            id:typetab
    Element Should Be Visible            id:moduletab

Scroll To Element
    [Arguments]  ${locator}
    ${x}=        Get Horizontal Position  ${locator}
    ${y}=        Get Vertical Position    ${locator}
    Execute Javascript  window.scrollTo(${x} - 100, ${y} - 100)
    Wait Until Element is visible  ${locator}    timeout=5s

*** Test Cases ***
Main navigation pages should render correctly
    Open browser                         ${URL}       ${BROWSER}
    Click Element                        id:nav-link-newscan
    Wait Until Page Contains             New Scan    timeout=5s
    New scan page should render
    Click Element                        id:nav-link-scans
    Wait Until Page Contains             Started     timeout=5s
    Scan list page should render
    Click Element                        id:nav-link-settings
    Wait Until Page Contains             Settings    timeout=5s
    Settings page should render

Scan info page should render correctly
    Create a module scan                 test scan info       spiderfoot.net           sfp_countryname
    Wait Until Page Contains             Browse               timeout=5s
    Wait Until Element Contains          scanstatusbadge      FINISHED                 timeout=10s
    Click Element                        id:btn-status
    Scan info Summary tab should render
    Click Element                        id:btn-browse
    Scan info Browse tab should render
    Click Element                        id:btn-graph
    Scan info Graph tab should render
    Click Element                        id:btn-info
    Scan info Settings tab should render
    Click Element                        id:btn-log
    Scan info Log tab should render

Scan list page should list scans
    Create a module scan                 test scan list       spiderfoot.net           sfp_countryname
    Click Element                        id:nav-link-scans
    Wait Until Page Contains             test scan list       timeout=5s

A sfp_dnsresolve scan should resolve INTERNET_NAME to IP_ADDRESS
    Create a module scan                 dns resolve          spiderfoot.net           sfp_dnsresolve
    Wait Until Page Contains             Browse               timeout=5s
    Wait Until Element Contains          scanstatusbadge      FINISHED                 timeout=10s
    Click Element                        id:btn-browse
    Scan info Browse tab should render
    Page Should Contain                  Domain Name
    Page Should Contain                  Internet Name
    Page Should Contain                  IP Address

A sfp_dnsresolve scan should reverse resolve IP_ADDRESS to INTERNET_NAME
    Create a module scan                 reverse resolve      1.1.1.1                  sfp_dnsresolve
    Wait Until Page Contains             Browse               timeout=5s
    Wait Until Element Contains          scanstatusbadge      FINISHED                 timeout=10s
    Click Element                        id:btn-browse
    Scan info Browse tab should render
    Page Should Contain                  Domain Name
    Page Should Contain                  Internet Name
    Page Should Contain                  IP Address

#A passive scan with unresolvable target internet name should fail
#    Create a use case scan               shouldnotresolve.doesnotexist.local  passive
#    Wait Until Page Contains             Browse           timeout=5s
#    Wait Until Element Contains          scanstatusbadge  RUNNING  timeout=10s
#    Click Element                        id:btn-browse
#    Page Should Contain                  Domain Name
#    Page Should Contain                  Internet Name
#    Page Should Contain                  IP Address

