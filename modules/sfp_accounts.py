# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_accounts
# Purpose:      Identify the existence of a given acount on various sites.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     18/02/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import time
import threading
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# Sites from recon-ng (https://bitbucket.org/LaNMaSteR53/recon-ng/src/f31164661322ec6b5fb0d014952e03abc34a1b01/data/profiler_sites.json?at=master)
# Original author Micah Hoffman (@WebBreacher)

sites = [
    {"r": "about.me", "u": "http://about.me/{0}", "gRC": "200", "gRT": "g.PAGE_USER_NAME =", "c": "social"},
    {"r": "AdultFriendFinder", "u": "http://imcservices.passion.com/profile/{0}", "gRC": "200", "gRT": "Member Profile - Adult FriendFinder</title>", "c": "dating"},
    {"r": "AdultMatchDoctor", "u": "http://www.adultmatchdoctor.com/profile_{0}.html", "gRC": "200", "gRT": "Last Activity:", "c": "dating"},
    {"r": "aNobil", "u": "http://www.anobii.com/{0}/books", "gRC": "200", "gRT": "- aNobii</title>", "c": "books"},
    {"r": "ask.fm", "u": "http://ask.fm/{0}", "gRC": "200", "gRT": "| ask.fm/", "c": "social"},
    {"r": "AudioBoom", "u": "http://audioboom.com/{0}", "gRC": "200", "gRT": "<title>audioBoom / ", "c": "video"},
    {"r": "authorSTREAM", "u": "http://www.authorstream.com/{0}/", "gRC": "200", "gRT": "Presentations on authorSTREAM", "c": "preso"},
    {"r": "badoo", "u": "http://badoo.com/{0}/", "gRC": "200", "gRT": "| Badoo</title>", "c": "social"},
    {"r": "Bebo", "u": "http://bebo.com/{0}", "gRC": "302", "gRT": "Location: /Profile.jsp?MemberId=", "c": "social"},
    {"r": "Behance", "u": "https://www.behance.net/{0}", "gRC": "200", "gRT": " on Behance\" />", "c": "social"},
    {"r": "Bitbucket", "u": "https://bitbucket.org/api/2.0/users/{0}", "gRC": "200", "gRT": "\"username\": ", "c": "coding"},
    {"r": "Bitly", "u": "http://bit.ly/u/{0}", "gRC": "200", "gRT": "| Public Profile</title>", "c": "url shortener"},
    {"r": "blinklist", "u": "https://app.blinklist.com/users/{0}", "gRC": "200", "gRT": " BlinkList Page.</title>", "c": "social"},
    {"r": "BLIP.fm", "u": "http://blip.fm/{0}", "gRC": "200", "gRT": "<title>Free Music | Listen to Music Online |", "c": "music"},
    {"r": "Blogmarks", "u": "http://blogmarks.net/user/{0}", "gRC": "200", "gRT": "<title>Blogmarks : Public marks from", "c": "bookmarks"},
    {"r": "Blogspot", "u": "http://{0}.blogspot.com", "gRC": "200", "gRT": "Blogger Template Style", "c": "blog"},
    {"r": "BodyBuilding.com", "u": "http://bodyspace.bodybuilding.com/{0}/", "gRC": "200", "gRT": "s BodySpace - Bodybuilding.com</title>", "c": "health"},
    {"r": "Buzznet", "u": "http://{0}.buzznet.com/user/", "gRC": "200", "gRT": "body class=\"userhome\"", "c": "social"},
    {"r": "cafemom", "u": "http://www.cafemom.com/home/{0}", "gRC": "200", "gRT": "h3 id=\"profile-user\"", "c": "social"},
    {"r": "CarDomain", "u": "http://www.cardomain.com/member/{0}/", "gRC": "200", "gRT": "s Profile in", "c": "hobby"},
    {"r": "CHEEZburger", "u": "http://profile.cheezburger.com/{0}", "gRC": "200", "gRT": "s Profile - Dashboard -", "c": "hobby"},
    {"r": "CodePlex", "u": "http://www.codeplex.com/site/users/view/{0}", "gRC": "200", "gRT": "property=\"profile:username\" />", "c": "coding"},
    {"r": "CoderStats", "u": "http://coderstats.net/github/{0}/", "gRC": "200", "gRT": "var repos = [{\"", "c": "coding"},
    {"r": "COLOURlovers", "u": "http://www.colourlovers.com/lover/{0}", "gRC": "200", "gRT": "Send A Love Note", "c": "hobby"},
    {"r": "Conferize", "u": "https://www.conferize.com/u/{0}/", "gRC": "200", "gRT": "| Conferize - Never miss a Conference</title>", "c": "social"},
    {"r": "copytaste", "u": "http://copytaste.com/profile/{0}", "gRC": "200", "gRT": " property=\"og:title\" content=\"", "c": "sharing"},
    {"r": "CruiseMates", "u": "http://www.cruisemates.com/forum/members/{0}.html", "gRC": "200", "gRT": "- View Profile: ", "c": "travel"},
    {"r": "Dailymotion", "u": "http://www.dailymotion.com/{0}", "gRC": "200", "gRT": " - Dailymotion</title>", "c": "video"},
    {"r": "DATEHOOKUP", "u": "http://www.datehookup.com/profile/{0}", "gRC": "200", "gRT": "DateHookup | Profile</title>", "c": "dating"},
    {"r": "Delicious", "u": "https://avosapi.delicious.com/api/v1/tags/bundles/{0}", "gRC": "200", "gRT": "\"owner_id\":\"", "c": "bookmarks"},
    {"r": "DeviantArt", "u": "http://{0}.deviantart.com/", "gRC": "200", "gRT": "s Journal\"", "c": "images"},
    {"r": "diigo", "u": "https://www.diigo.com/profile/{0}", "gRC": "200", "gRT": " Public Profile in the Diigo Community</title>", "c": "social"},
    {"r": "Diply", "u": "http://diply.com/api/users/{0}", "gRC": "200", "gRT": "{\"Id\"", "c": "shopping"},
    {"r": "Disqus", "u": "https://disqus.com/by/{0}/", "gRC": "200", "gRT": "<title>Disqus</title>", "c": "social"},
    {"r": "DIY", "u": "https://diy.org/{0}", "gRC": "200", "gRT": "iphone\" content=\"diy://diy.org/", "c": "video"},
    {"r": "Docstoc", "u": "http://www.docstoc.com/profile/{0}", "gRC": "200", "gRT": "h1 class=\"name\">", "c": "business"},
    {"r": "dribble", "u": "https://www.dribbble.com/players/{0}", "gRC": "200", "gRT": "<title>Dribbble - ", "c": "images"},
    {"r": "eBay", "u": "http://www.ebay.com/usr/{0}", "gRC": "200", "gRT": "on eBay</title>", "c": "shopping"},
    {"r": "EightBit", "u": "http://eightbit.me/{0}", "gRC": "200", "gRT": "on EightBit</title>", "c": "gaming"},
    {"r": "Engadget", "u": "http://www.engadget.com/profile/{0}/", "gRC": "200", "gRT": "profile - Engadget</title>", "c": "tech"},
    {"r": "Epinions", "u": "http://www.epinions.com/user-{0}?sb=1", "gRC": "200", "gRT": "s Profile Reviews and Products | Epinions.com</title>", "c": "social"},
    {"r": "EPORNER", "u": "http://www.eporner.com/profile/{0}/", "gRC": "200", "gRT": ">Recently watched</a>", "c": "XXX PORN XXX"},
    {"r": "Etsy", "u": "https://www.etsy.com/people/{0}", "gRC": "200", "gRT": " on Etsy</title>", "c": "shopping"},
    {"r": "Examine.com", "u": "http://examine.com/user/{0}/", "gRC": "200", "gRT": "Profile | Examine.com</title>", "c": "health"},
    {"r": "families.com", "u": "http://www.families.com/author/{0}", "gRC": "200", "gRT": "  </title>", "c": "news"},
    {"r": "fanpop", "u": "http://www.fanpop.com/fans/{0}", "gRC": "200", "gRT": "s Profile Page</title>", "c": "movies"},
    {"r": "Favstar", "u": "http://favstar.fm/users/{0}", "gRC": "200", "gRT": "Best Tweets</title>", "c": "social"},
    {"r": "FFFFOUND!", "u": "http://ffffound.com/home/{0}/found/", "gRC": "200", "gRT": "<title>FFFFOUND!</title>", "c": "image"},
    {"r": "Flavors", "u": "http://{0}.flavors.me", "gRC": "200", "gRT": ": Flavors.me", "c": "blog"},
    {"r": "Flickr", "u": "https://www.flickr.com/photos/{0}/", "gRC": "200", "gRT": "s Photostream</title>", "c": "images"},
    {"r": "Foodspotting", "u": "http://www.foodspotting.com/{0}", "gRC": "200", "gRT": " - Foodspotting</title>", "c": "social"},
    {"r": "Fotolog", "u": "http://www.fotolog.com/{0}/", "gRC": "200", "gRT": " - Fotolog</title>", "c": "images"},
    {"r": "Foursquare", "u": "https://foursquare.com/{0}", "gRC": "200", "gRT": "on Foursquare</title>", "c": "location"},
    {"r": "freesound", "u": "http://www.freesound.org/people/{0}/", "gRC": "200", "gRT": "START of Content area", "c": "music"},
    {"r": "FriendFeed", "u": "http://friendfeed.com/{0}", "gRC": "200", "gRT": " - FriendFeed</title>", "c": "social"},
    {"r": "FriendFinder-X", "u": "http://www.friendfinder-x.com/profile/{0}", "gRC": "200", "gRT": "Member Profile - FriendFinder-x</title>", "c": "dating"},
    {"r": "FunnyOrDie", "u": "http://www.funnyordie.com/{0}", "gRC": "200", "gRT": " - Home on Funny or Die</title>", "c": "video"},
    {"r": "Garmin connect", "u": "http://connect.garmin.com/modern/profile/{0}", "gRC": "200", "gRT": "VIEWER_USERPREFERENCES =", "c": "exercise"},
    {"r": "Geocaching", "u": "http://www.geocaching.com/seek/nearest.aspx?u={0}", "gRC": "200", "gRT": "By Username (Hidden) - User:", "c": "hobby"},
    {"r": "GETItON", "u": "http://getiton.com/profile/{0}", "gRC": "200", "gRT": "s Profile</title>", "c": "dating"},
    {"r": "GitHub", "u": "https://api.github.com/users/{0}", "gRC": "200", "gRT": "\"login\": \"", "c": "coding"},
    {"r": "GodTube", "u": "http://www.godtube.com/{0}/", "gRC": "200", "gRT": "Last Visit Date:</span>", "c": "video"},
    {"r": "gogobot", "u": "http://www.gogobot.com/user/{0}", "gRC": "200", "gRT": "Travel Tips &amp; Activities", "c": "travel"},
    {"r": "goodreads", "u": "http://www.goodreads.com/{0}", "gRC": "301", "gRT": "www.goodreads.com/user/show/", "c": "books"},
    {"r": "Gravatar", "u": "http://en.gravatar.com/profiles/{0}.json", "gRC": "200", "gRT": "\"displayName\":", "c": "images"},
    {"r": "howaboutwe", "u": "http://www.howaboutwe.com/users/{0}", "gRC": "200", "gRT": "location font_20\"", "c": "dating"},
    {"r": "HubPages", "u": "http://{0}.hubpages.com/", "gRC": "200", "gRT": "on HubPages</title>", "c": "blog"},
    {"r": "I-am-pregnant", "u": "http://www.i-am-pregnant.com/vip/{0}", "gRC": "200", "gRT": "This is the stylesheet for your pages. Add your own rules below this line", "c": "health"},
    {"r": "IFTTT", "u": "https://ifttt.com/p/{0}/shared", "gRC": "200", "gRT": "s Published Recipes - IFTTT", "c": "hobby"},
    {"r": "ImageShack", "u": "https://imageshack.com/user/{0}", "gRC": "200", "gRT": "s Images</title>", "c": "image"},
    {"r": "imgur", "u": "http://imgur.com/user/{0}", "gRC": "200", "gRT": "on Imgur</title>", "c": "images"},
    {"r": "InsaneJournal", "u": "http://{0}.insanejournal.com/profile", "gRC": "200", "gRT": "<title>User Info</title>", "c": "social"},
    {"r": "Instagram", "u": "http://instagram.com/{0}", "gRC": "200", "gRT": "on Instagram\" />", "c": "images"},
    {"r": "instructables", "u": "http://www.instructables.com/member/{0}/", "gRC": "200", "gRT": "<title>Instructables Member:", "c": "hobby"},
    {"r": "Internet Archive", "u": "http://archive.org/search.php?query=subject%%3A%%22{0}%%22", "gRC": "200", "gRT": "<tr class=\"hitRow\">", "c": "search"},
    {"r": "interpals", "u": "http://www.interpals.net/{0}", "gRC": "200", "gRT": "s Profile</title>", "c": "hobby"},
    {"r": "JamBase", "u": "http://www.jambase.com/Fans/{0}", "gRC": "200", "gRT": "on JamBase", "c": "music"},
    {"r": "kaboodle", "u": "http://www.kaboodle.com/{0}", "gRC": "200", "gRT": "s Kaboodle profile</title>", "c": "shopping"},
    {"r": "Keybase", "u": "https://keybase.io/{0}", "gRC": "200", "gRT": "| Keybase</title>", "c": "business"},
    {"r": "Kik!", "u": "http://www.kik.com/u/{0}", "gRC": "200", "gRT": "Hey! I'm on Kik - my username is", "c": "social"},
    {"r": "Klout", "u": "https://klout.com/{0}", "gRC": "200", "gRT": "| Klout.com\">", "c": "social"},
    {"r": "Kongregate", "u": "http://www.kongregate.com/accounts/{0}", "gRC": "200", "gRT": "s profile on Kongregate</title>", "c": "gaming"},
    {"r": "Lanyrd", "u": "http://lanyrd.com/profile/{0}/", "gRC": "200", "gRT": "s conference talks and presentations | Lanyrd</title>", "c": "social"},
    {"r": "Last.fm", "u": "http://www.last.fm/user/{0}", "gRC": "200", "gRT": "s Music Profile - Users", "c": "music"},
    {"r": "LawOfAttraction", "u": "http://www.lawofattractionsingles.com/{0}", "gRC": "200", "gRT": "s profile on Law Of Attraction Singles</title>", "c": "dating"},
    {"r": "LibraryThing", "u": "http://www.librarything.com/profile/{0}", "gRC": "200", "gRT": "| LibraryThing</title>", "c": "books"},
    {"r": "LinkedIn", "u": "https://www.linkedin.com/in/{0}", "gRC": "200", "gRT": "summary=\"Overview for ", "c": "social"},
    {"r": "LIVEJASMIN", "u": "http://www.livejasmin.com/perfinfo.php?performerid={0}", "gRC": "200", "gRT": "Live Sex - Hot Live Sex Shows!... LiveJasmin ..</title>", "c": "XXX PORN XXX"},
    {"r": "Marketing Land", "u": "http://marketingland.com/author/{0}", "gRC": "200", "gRT": "property=\"og:url\" content=", "c": "business"},
    {"r": "Match.com", "u": "http://www.match.com/Profile/Display/About//?handle={0}&tp=prtbk", "gRC": "200", "gRT": "property=\"og:title\" content=\"", "c": "dating"},
    {"r": "mate1", "u": "http://www.mate1.com/profiles/{0}", "gRC": "200", "gRT": "basicInfoTitle\">Basic Info", "c": "dating"},
    {"r": "Medium", "u": "https://medium.com/@{0}", "gRC": "200", "gRT": "name=\"description\" content=\"", "c": "news"},
    {"r": "Meetzur", "u": "http://www.meetzur.com/{0}", "gRC": "200", "gRT": "MEETZUR_PROFILE_300x250", "c": "dating"},
    {"r": "Mixcloud", "u": "http://www.mixcloud.com/{0}/", "gRC": "200", "gRT": "s Favorites | Mixcloud</title>", "c": "music"},
    {"r": "Mixlr", "u": "http://mixlr.com/{0}/", "gRC": "200", "gRT": "is on Mixlr. Mixlr is a simple way to share live", "c": "music"},
    {"r": "Mod DB", "u": "http://www.moddb.com/members/{0}", "gRC": "200", "gRT": "View the Mod DB  member ", "c": "gaming"},
    {"r": "Muck Rack", "u": "http://muckrack.com/{0}", "gRC": "200", "gRT": "on Muck Rack</title>", "c": "news"},
    {"r": "Muzy", "u": "http://{0}.muzy.com/", "gRC": "200", "gRT": "http://muzy-users.s3.amazonaws.com", "c": "images"},
    {"r": "MyAnimeList", "u": "http://myanimelist.net/profile/{0}", "gRC": "200", "gRT": "s Profile - MyAnimeList.net</title>", "c": "hobby"},
    {"r": "MyBuilder.com", "u": "http://www.mybuilder.com/profile/view/{0}", "gRC": "200", "gRT": "s profile</title>", "c": "jobs"},
    {"r": "myfitnesspal", "u": "http://www.myfitnesspal.com/user/{0}/status", "gRC": "200", "gRT": "s profile | MyFitnessPal.com</title>", "c": "health"},
    {"r": "myLot", "u": "http://www.mylot.com/{0}", "gRC": "200", "gRT": "on myLot</title>", "c": "social"},
    {"r": "myspace", "u": "https://www.myspace.com/{0}", "gRC": "200", "gRT": ") on Myspace</title>", "c": "social"},
    {"r": "netvibes", "u": "https://www.netvibes.com/{0}", "gRC": "200", "gRT": "s Public Page</title>", "c": "social"},
    {"r": "NEWSVINE", "u": "http://{0}.newsvine.com/_tps/_author/profile", "gRC": "200", "gRT": " Profile</title>", "c": "blog"},
    {"r": "OkCupid", "u": "http://www.okcupid.com/profile/{0}", "gRC": "200", "gRT": "<title>OkCupid |", "c": "dating"},
    {"r": "Open Source Report Card", "u": "https://osrc.dfm.io/{0}/", "gRC": "200", "gRT": "s Open Source Report Card</title>", "c": "coding"},
    {"r": "Overcast Network", "u": "https://oc.tc/{0}", "gRC": "200", "gRT": "https://avatar.oc.tc/", "c": "gaming"},
    {"r": "Pandora", "u": "http://www.pandora.com/profile/{0}", "gRC": "200", "gRT": "div class=\"profile_container_static\"", "c": "music"},
    {"r": "Photoblog!", "u": "http://www.photoblog.com/{0}/", "gRC": "200", "gRT": "photoblog_username = \"", "c": "images"},
    {"r": "PhotoBucket", "u": "http://smg.photobucket.com/user/{0}/profile/", "gRC": "200", "gRT": " Pictures, Photos & Images | Photobucket</title>", "c": "images"},
    {"r": "Picasa", "u": "https://picasaweb.google.com/{0}/", "gRC": "302", "gRT": "s Picasa Web Gallery\"/>", "c": "images"},
    {"r": "PictureTrail", "u": "http://picturetrail.com/homepage/{0}", "gRC": "200", "gRT": "<title>PictureTrail</title>", "c": "images"},
    {"r": "PinkBike", "u": "http://www.pinkbike.com/u/{0}/", "gRC": "200", "gRT": "on Pinkbike</title>", "c": "hobby"},
    {"r": "Pinterest", "u": "https://www.pinterest.com/{0}/", "gRC": "200", "gRT": "on Pinterest</title>", "c": "social"},
    {"r": "Plancast", "u": "http://plancast.com/{0}/", "gRC": "200", "gRT": "<title>Attend Events with", "c": "social"},
    {"r": "plaxo", "u": "http://www.plaxo.com/profile/showPublic/{0}", "gRC": "200", "gRT": "s Public Profile</title>", "c": "social"},
    {"r": "Playlists.net", "u": "http://playlists.net/members/{0}", "gRC": "200", "gRT": "<title>Profile for ", "c": "music"},
    {"r": "Plurk", "u": "http://www.plurk.com/{0}", "gRC": "200", "gRT": "] on Plurk - Plurk</title>", "c": "social"},
    {"r": "POF", "u": "http://www.pof.com/basicusersearch.aspx?usernamet={0}", "gRC": "200", "gRT": "div class=\"results\"", "c": "dating"},
    {"r": "PORN.COM", "u": "http://www.porn.com/profile/{0}", "gRC": "200", "gRT": "Member Profile - PORN.COM</title>", "c": "XXX PORN XXX"},
    {"r": "Pornhub", "u": "http://www.pornhub.com/users/{0}", "gRC": "200", "gRT": "s Profile - Pornhub.com</title>", "c": "XXX PORN XXX"},
    {"r": "Printfection", "u": "http://www.printfection.com/{0}/", "gRC": "200", "gRT": "- Printfection.com</title>", "c": "shopping"},
    {"r": "raptr", "u": "http://raptr.com/{0}/about", "gRC": "200", "gRT": "'s Profile - Raptr</title>", "c": "gaming"},
    {"r": "Rate Your Music", "u": "http://rateyourmusic.com/~{0}", "gRC": "200", "gRT": "Rate Your Music</title>", "c": "music"},
    {"r": "Readability", "u": "https://www.readability.com/{0}/", "gRC": "200", "gRT": "on Readability", "c": "social"},
    {"r": "reddit", "u": "http://www.reddit.com/user/{0}/", "gRC": "200", "gRT": "<title>overview for ", "c": "news"},
    {"r": "RedTube", "u": "http://www.redtube.com/{0}", "gRC": "200", "gRT": "RedTube - Home of Porn - Free Porn</title>", "c": "XXX PORN XXX"},
    {"r": "Reunion.com", "u": "http://www.reunion.com/{0}/", "gRC": "200", "gRT": "@ Reunion.com</title>", "c": "social"},
    {"r": "scratch", "u": "http://scratch.mit.edu/users/{0}/", "gRC": "200", "gRT": "on Scratch</title>", "c": "coding"},
    {"r": "Security Street", "u": "https://community.rapid7.com/people/{0}", "gRC": "200", "gRT": "s Profile     | SecurityStreet", "c": "social"},
    {"r": "setlist.fm", "u": "http://www.setlist.fm/user/{0}", "gRC": "200", "gRT": "s setlist.fm | setlist.fm</title>", "c": "music"},
    {"r": "shelfari", "u": "http://www.shelfari.com/{0}", "gRC": "200", "gRT": "s Profile</title>", "c": "books"},
    {"r": "Shopcade", "u": "http://www.shopcade.com/{0}", "gRC": "200", "gRT": ") on Shopcade</title", "c": "shopping"},
    {"r": "Slashdot", "u": "http://slashdot.org/~{0}", "gRC": "200", "gRT": " - Slashdot User</title>", "c": "news"},
    {"r": "slideshare", "u": "http://www.slideshare.net/{0}", "gRC": "200", "gRT": "s presentations</title>", "c": "presos"},
    {"r": "SmugMug", "u": "http://{0}.smugmug.com", "gRC": "200", "gRT": "pageon: homepage", "c": "images"},
    {"r": "smule", "u": "http://www.smule.com/{0}/", "gRC": "200", "gRT": "s Profile on Smule</title>", "c": "music"},
    {"r": "snooth", "u": "http://www.snooth.com/profiles/{0}/", "gRC": "301", "gRT": "Location: http://www.snooth.com/profiles/John/", "c": "food"},
    {"r": "SoldierX", "u": "https://www.soldierx.com/hdb/{0}", "gRC": "200", "gRT": "div id=\"node-", "c": "hacker"},
    {"r": "SoundCloud", "u": "https://soundcloud.com/{0}", "gRC": "200", "gRT": "profile - Hear the world", "c": "music"},
    {"r": "Soup", "u": "http://{0}.soup.io", "gRC": "200", "gRT": "s soup</title>", "c": "blog"},
    {"r": "SourceForge", "u": "http://sourceforge.net/u/{0}/profile/", "gRC": "200", "gRT": " / Profile</title>", "c": "coding"},
    {"r": "Speaker Deck", "u": "https://speakerdeck.com/{0}", "gRC": "200", "gRT": "<title>Presentations by", "c": "presos"},
    {"r": "sporcle", "u": "http://www.sporcle.com/user/{0}/connections", "gRC": "200", "gRT": "id='UserBox'>", "c": "gaming"},
    {"r": "Steam", "u": "http://steamcommunity.com/id/{0}", "gRC": "200", "gRT": "g_rgProfileData =", "c": "gaming"},
    {"r": "StumbleUpon", "u": "http://www.stumbleupon.com/stumbler/{0}", "gRC": "200", "gRT": "s Likes | StumbleUpon.com</title>", "c": "social"},
    {"r": "stupidcancer", "u": "http://stupidcancer.org/community/profile/{0}", "gRC": "200", "gRT": "- Stupid Cancer Community</title>", "c": "health"},
    {"r": "Technorati", "u": "http://technorati.com/author/{0}/", "gRC": "200", "gRT": " | Technorati</title>", "c": "business"},
    {"r": "TF2 Backpack Examiner", "u": "http://www.tf2items.com/id/{0}/", "gRC": "200", "gRT": "<title>TF2 Backpack -", "c": "gaming"},
    {"r": "theguardian", "u": "https://id.theguardian.com/profile/{0}/public", "gRC": "200", "gRT": "profile | The Guardian", "c": "news"},
    {"r": "thesixtyone", "u": "http://www.thesixtyone.com/{0}/", "gRC": "200", "gRT": "s music on thesixtyone", "c": "music"},
    {"r": "tribe", "u": "http://people.tribe.net/{0}", "gRC": "200", "gRT": "Profile - tribe.net</title>", "c": "dating"},
    {"r": "tripadvisor", "u": "http://www.tripadvisor.com/members/{0}", "gRC": "200", "gRT": "<title>Member Profile - ", "c": "travel"},
    {"r": "Tripit", "u": "https://www.tripit.com/people/{0}#/profile/basic-info", "gRC": "200", "gRT": "Travel Profile - TripIt</title>", "c": "travel"},
    {"r": "tumblr", "u": "http://{0}.tumblr.com", "gRC": "200", "gRT": "X-Tumblr-User:", "c": "images"},
    {"r": "Twitpic", "u": "http://twitpic.com/photos/{0}", "gRC": "200", "gRT": "<title>Twitpic /", "c": "social"},
    {"r": "Twitter", "u": "https://twitter.com/{0}", "gRC": "200", "gRT": "| Twitter</title>", "c": "social"},
    {"r": "twtrland", "u": "http://twtrland.com/profile/{0}/", "gRC": "200", "gRT": "var query_global =", "c": "social"},
    {"r": "untappd", "u": "https://untappd.com/user/{0}/", "gRC": "200", "gRT": "on Untappd</title>", "c": "food"},
    {"r": "USTREAM", "u": "http://www.ustream.tv/channel/{0}", "gRC": "200", "gRT": "on USTREAM:", "c": "video"},
    {"r": "viddler", "u": "http://www.viddler.com/explore/{0}/", "gRC": "200", "gRT": "s profile - Viddler</title>", "c": "video"},
    {"r": "VideoLike", "u": "http://videolike.org/video/{0}", "gRC": "200", "gRT": ":: VideoLike</title>", "c": "video"},
    {"r": "vidme", "u": "https://vid.me/u/{0}", "gRC": "200", "gRT": "s videos - vidme</title>", "c": "video"},
    {"r": "Vimeo", "u": "http://vimeo.com/{0}", "gRC": "200", "gRT": "on Vimeo</title>", "c": "video"},
    {"r": "Vine", "u": "https://platform.vine.co/api/users/profiles/vanity/{0}", "gRC": "200", "gRT": "success\": true", "c": "video"},
    {"r": "VisualizeUs", "u": "http://vi.sualize.us/{0}/", "gRC": "200", "gRT": "favorite pictures on VisualizeUs</title>", "c": "images"},
    {"r": "Voices.com", "u": "https://www.voices.com/people/{0}", "gRC": "200", "gRT": "/assets/images/branding/default_profile_avatar", "c": "business"},
    {"r": "Wanelo", "u": "http://wanelo.com/{0}", "gRC": "200", "gRT": "on Wanelo</title>", "c": "shopping"},
    {"r": "wattpad", "u": "http://www.wattpad.com/user/{0}", "gRC": "200", "gRT": "- Wattpad </title>", "c": "social"},
    {"r": "WeeWorld", "u": "http://www.weeworld.com/home/{0}", "gRC": "200", "gRT": "s Home) - WeeMee", "c": "gaming"},
    {"r": "Wefollow", "u": "http://wefollow.com/{0}", "gRC": "200", "gRT": "on Wefollow</title>", "c": "social"},
    {"r": "wishlistr", "u": "http://www.wishlistr.com/profile/{0}/", "gRC": "200", "gRT": "s profile</title>", "c": "shopping"},
    {"r": "woot!", "u": "http://deals.woot.com/deals/users/{0}", "gRC": "200", "gRT": "div class=\"deal forumList clearfix", "c": "shopping"},
    {"r": "WordPress", "u": "https://profiles.wordpress.org/{0}", "gRC": "200", "gRT": "alt=\"Profile picture of", "c": "blog"},
    {"r": "WordPress Support", "u": "https://wordpress.org/support/profile/{0}", "gRC": "200", "gRT": "User Favorites: ", "c": "support"},
    {"r": "Xanga", "u": "http://{0}.xanga.com/", "gRC": "200", "gRT": "s Xanga Site | Just another Xanga site</title>", "c": "blog"},
    {"r": "Xbox Gamertag", "u": "http://www.xboxgamertag.com/search/{0}/", "gRC": "200", "gRT": " - Xbox Live Gamertag </title>", "c": "gaming"},
    {"r": "XboxLiveScore", "u": "http://www.xboxlivescore.com/profile/{0}", "gRC": "200", "gRT": "on the Gamerscore Leaderboard</title>", "c": "gaming"},
    {"r": "Xfire Main", "u": "http://www.xfire.com/{0}", "gRC": "200", "gRT": "<h1 class=\"username\">", "c": "gaming"},
    {"r": "Xfire Social", "u": "http://social.xfire.com/profile/{0}", "gRC": "200", "gRT": "s Profile</title>", "c": "gaming"},
    {"r": "xHamster", "u": "http://xhamster.com/user/{0}", "gRC": "200", "gRT": "s Profile</title>", "c": "XXX PORN XXX"},
    {"r": "XVIDEOS", "u": "http://www.xvideos.com/profiles/{0}", "gRC": "200", "gRT": "id_user = ", "c": "XXX PORN XXX"},
    {"r": "Yahoo Email", "u": "https://na.edit.yahoo.com/reg_json?PartnerName=yahoo_default&RequestVersion=1&AccountID={0}@yahoo.com&ApiName=ValidateFields&intl=us", "gRC": "200", "gRT": "\"SUCCESS\"", "c": "email"},
    {"r": "YouTube", "u": "https://www.youtube.com/user/{0}/videos", "gRC": "200", "gRT": "- YouTube</title>", "c": "video"},
    {"r": "Zooppa", "u": "http://zooppa.com/en-us/users/{0}", "gRC": "200", "gRT": "<title>Zooppa</title>", "c": "social"}
]

class sfp_accounts(SpiderFootPlugin):
    """Accounts:Footprint:Look for possible associated accounts on nearly 200 websites like Ebay, Slashdot, reddit, etc."""

    # Default options
    opts = {
        "generic": ["root", "abuse", "sysadm", "sysadmin", "noc", "support", "admin",
                    "contact", "help", "flame", "test", "info", "sales", "hostmaster"],
        "ignoredict": True,
        "maxthreads": 50
    }

    # Option descriptions
    optdescs = {
        "generic": "Generic internal accounts to not bother looking up externally.",
        "ignoredict": "Don't bother looking up internal names externally that are just stand-alone first names.",
        "maxthreads": "Maximum number of simultaneous threads (one thread per site the account is being checked on.)"
    }

    results = dict()
    reportedUsers = list()
    siteResults = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.commonNames = list()
        self.reportedUsers = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

            names = open(self.sf.myPath() + "/ext/ispell/names.list", 'r')
            lines = names.readlines()
            for item in lines:
                self.commonNames.append(item.strip().lower())
            names.close()

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["EMAILADDR", "DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["USERNAME", "ACCOUNT_EXTERNAL_OWNED", 
                "ACCOUNT_EXTERNAL_USER_SHARED"]

    def checkSite(self, name, site):
        url = site['u'].format(name)
        retname = site['r'] + " (" + site['c'] + ")\n<SFURL>" + \
                site['u'].format(name) + "</SFURL>"

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'], noLog=True)

        if str(res['code']) == site['gRC'] and site['gRT'] in res['content']:
            self.siteResults[retname] = True
        else:
            self.siteResults[retname] = False

    def threadSites(self, name, siteList):
        ret = list()
        self.siteResults = dict()
        running = True
        i = 0
        t = []

        for site in siteList:
            if self.checkForStop():
                return None
            self.sf.info("Spawning thread to check site: " + site['r'] + \
                        " / " + site['u'].format(name))
            t.append(threading.Thread(name='sfp_accounts_' + site['r'],
                                      target=self.checkSite, args=(name, site)))
            t[i].start()
            i += 1

        # Block until all threads are finished
        while running:
            found = False
            for rt in threading.enumerate():
                if rt.name.startswith("sfp_accounts_"):
                    found = True

            if not found:
                running = False

            time.sleep(2) 

        # Return once the scanning has completed
        return self.siteResults

    def batchSites(self, name):
        global sites
        i = 0
        res = list()
        siteList = list()

        for site in sites:
            if i >= self.opts['maxthreads']:
                data = self.threadSites(name, siteList)
                if data == None:
                    return res

                for ret in data.keys():
                    if data[ret]:
                        res.append(ret)
                i = 0
                siteList = list()

            siteList.append(site)
            i += 1

        return res

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        users = list()

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData not in self.results.keys():
            self.results[eventData] = True
        else:
            return None

        if eventName == "DOMAIN_NAME":
            kw = self.sf.domainKeyword(eventData, self.opts['_internettlds'])

            res = self.batchSites(kw)
            for site in res:
                evt = SpiderFootEvent("ACCOUNT_EXTERNAL_OWNED", site,
                                      self.__name__, event)
                self.notifyListeners(evt)
            return None

        if eventName == "EMAILADDR":
            name = eventData.split("@")[0].lower()
            if self.opts['generic'] is list() and name in self.opts['generic']:
                self.sf.debug(name + " is a generic account name, skipping.")
                return None

            if self.opts['ignoredict'] and name in self.commonNames:
                self.sf.debug(name + " is found in our name dictionary, skipping.")
                return None

            users.append(name)
            if "." in name:
                # steve.micallef -> smicallef
                users.append(str(name[0] + name.split(".")[1]).lower())

            for user in users:
                if user not in self.reportedUsers:
                    evt = SpiderFootEvent("USERNAME", user, self.__name__, event)
                    self.notifyListeners(evt)
                    self.reportedUsers.append(user)

                res = self.batchSites(user)

                for site in res:
                    evt = SpiderFootEvent("ACCOUNT_EXTERNAL_USER_SHARED", site,
                                          self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_accounts class
