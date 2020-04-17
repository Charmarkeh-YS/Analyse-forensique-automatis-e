import urllib.request
import re
def getNote(url):
    response=urllib.request.urlopen("https://www.mywot.com/scorecard/{}".format(url))
    html=response.read()
    i=0
    for l in html :
        if(html[i:i+59]==b'class="StyledScorecardHeader__Detail-sc-1j5xgrs-11 jivKcv">'):
            i+=59
            break
        i+=1
    note=html[i:i+3]
    return note

