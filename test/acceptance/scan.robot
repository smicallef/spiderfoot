# To run the tests, start sf web interface:
#   python3 ./sf.py -l 127.0.0.1:5001
# then run robot (override the BROWSER variable if necessary):
#   robot --variable BROWSER:Firefox --outputdir results scan.robot

*** Settings ***
Library         SeleniumLibrary

*** Variables ***
${BROWSER}     Firefox
${HOST}        127.0.0.1
${PORT}        5001

*** Keywords ***
Create a simple DNS resolver scan
    [Arguments]             ${scan_target}
    Open browser            http://${HOST}:${PORT}/newscan  ${BROWSER}
    Press Keys              name:scanname                   ${scan_target}
    Press Keys              name:scantarget                 ${scan_target}
    Click Element           id:moduletab
    Click Element           id:btn-deselect-all
    Scroll To Element       id:module_sfp_dnsresolve
    Set Focus To Element    id:module_sfp_dnsresolve
    Click Element           id:module_sfp_dnsresolve
    Scroll To Element       id:btn-run-scan
    Click Element           id:btn-run-scan

Create a passive scan
    [Arguments]             ${scan_target}
    Open browser            http://${HOST}:${PORT}/newscan  ${BROWSER}
    Press Keys              name:scanname                   ${scan_target}
    Press Keys              name:scantarget                 ${scan_target}
    Click Element           id:usecase_passive
    Scroll To Element       id:btn-run-scan
    Click Element           id:btn-run-scan
 
Scroll To Element
    [Arguments]  ${locator}
    ${x}=        Get Horizontal Position  ${locator}
    ${y}=        Get Vertical Position    ${locator}
    Execute Javascript  window.scrollTo(${x} - 100, ${y} - 100)
    Wait Until Element is visible  ${locator}    timeout=5s

*** Test Cases ***
A sfp_dnsresolve scan should resolve INTERNET_NAME to IP_ADDRESS
    Create a simple DNS resolver scan    spiderfoot.net
    Wait Until Page Contains             Browse           timeout=5s
    Wait Until Element Contains          scanstatusbadge  FINISHED  timeout=5s
    Click Element                        id:btn-browse
    Page Should Contain                  Domain Name
    Page Should Contain                  Internet Name
    Page Should Contain                  IP Address
    Close All Browsers

A sfp_dnsresolve scan should reverse resolve IP_ADDRESS to INTERNET_NAME
    Create a simple DNS resolver scan    1.1.1.1
    Wait Until Page Contains             Browse           timeout=5s
    Wait Until Element Contains          scanstatusbadge  FINISHED  timeout=5s
    Click Element                        id:btn-browse
    Page Should Contain                  Domain Name
    Page Should Contain                  Internet Name
    Page Should Contain                  IP Address
    Close All Browsers

#A passive scan with unresolvable target internet name should fail
#    Create a passive scan                shouldnotresolve.doesnotexist.local
#    Wait Until Page Contains             Browse           timeout=5s
#    Wait Until Element Contains          scanstatusbadge  RUNNING  timeout=5s
#    Click Element                        id:btn-browse
#    Page Should Contain                  Domain Name
#    Page Should Contain                  Internet Name
#    Page Should Contain                  IP Address
#    Close All Browsers

