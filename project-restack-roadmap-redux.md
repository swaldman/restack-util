# Project Restack Roadmap Redux

### Table of Contents

* [1\. Untemplate](#1-Untemplate)
* [2\. Unstatic](#2-Unstatic)
* [2&frac12;. "Simple" Blog](#2%C2%BD-%E2%80%9CSimple%E2%80%9D-Blog)
* [3\. Feedletter](#3-Feedletter)
* [4\. Protopost (tentative name)](#4-Protopost-tentative-name)
* [5\. Seismic (tentative name)](#5-Seismic-tentative-name)
* [6\. Paid support or subscriptions](#6-Paid-support-or-subscriptions)
* [Appendix: Cross-blog commenting](#Appendix-Cross-site-commenting)

---

### 1. Untemplate

**Status:** <span style="color: green; font-weight: bold">Complete</span> (though subject continuing maintenance and improvement)

<div style="margin-left: 1em; border-left: 2px solid orange; padding-left: 1em;">

Pretty much any project that's going to generate text will want some kind of a templating system. Untemplate is a minimalist templating system with very rich hooks for integrating into larger systems (like static site generators, or newsletter platforms and other systems that generate rich HTML e-mail.)

Each template converts into a pure Scala function, and the templating systen is a thin wrapper over the Scala language, so manipulations can be as simple or complex as you like.

* [Documentation](https://github.com/swaldman/untemplate-doc#readme)
* [Source code](https://github.com/swaldman/untemplate)

**Some simple examples:**

* office-hours-interfluidity \[[source](https://github.com/swaldman/office-hours-interfluidity/tree/main/untemplate/com/interfluidity/officehours/mail)\]
* mchange-sysdamin \[[source](https://github.com/swaldman/mchange-sysadmin-scala)\]
* fossilphant \[[source](https://github.com/swaldman/fossilphant)\]

(Some of the projects below are less simple example.)

</div>

---

### 2. Unstatic

**Status:** <span style="color: green; font-weight: bold">Complete</span> (though subject continuing maintenance and improvement)

<div style="margin-left: 1em; border-left: 2px solid orange; padding-left: 1em">

_Unstatic_ is a Scala library for building static site generators. Fundamentally, in a small Scala class, users define a set of "[endpoint bindings](https://github.com/swaldman/unstatic/blob/main/ztapir/src/unstatic/ztapir/ZTEndpointBinding.scala)", each of which specifies a path it will take on the generated site, a ZServerEndpoint that would serve the content via [tapir](https://tapir.softwaremill.com/en/latest/), and a means to generate the content as a static file. (The tapir endpoint enables serving the site dynamically, for quick updates while writing or developing.)

_Unstatic_ includes utilities to convert markdown source to HTML and integrates easily with [untemplate](#1-Untemplate)

* [Source code](https://github.com/swaldman/unstatic/)

**Some simple examples:**

* Moti Flooring \[[site](https://www.motiflooring.com/)\] \[[source](https://github.com/motiflooring/motiflooring.com/blob/main/motiflooring/src/com/motiflooring/site/MotiflooringSite.scala)\]
* Tampa Java Users' Group Scala Talk \[[site](https://www.interfluidity.com/uploads/2023/05/tjug-scala-talk-2023-05-11/)\] \[[source](https://github.com/swaldman/tjug-scala-talk-2023-05-11/blob/main/tjug/src/tjug/TjugSite.scala)\]

</div>

---

### 2&frac12;. "Simple" Blog

**Status:** <span style="color: green; font-weight: bold">Complete</span> (though subject continuing maintenance and improvement)

<div style="margin-left: 1em; border-left: 2px solid orange; padding-left: 1em">

"Simple" blog, is for now, a submodule of [_unstatic_](#2-Unstatic), though I may pull it out into a separate project, and perhaps change the name. A SimpleBlog outputs _unstatic_ endpoint bindings that build increasingly full-featured (and less simple) blogs from user-defined [untemplates](#1-Untemplate).

Blogs generate rich, full-content RSS via [_audiofluidity-rss_](https://github.com/swaldman/audiofluidity-rss), including [_"iffy" extensions_](https://tech.interfluidity.com/xml/iffy/index.html).

Blogs support features including [the ability to](https://tech.interfluidity.com/xml/iffy/index.html) spawn "sprouts", track major revisions, and generate diffs. Major revisions can be [re-announced on RSS via "synthetic" posts](https://tech.interfluidity.com/2024/06/20/sprouted/index.html) (whose announcement via more intrusive channels, like e-mail, can be suppressed).

Generation of [all-item](https://tech.interfluidity.com/2025/01/06/supporting-all-item-rss/index.html) and [single-item](https://tech.interfluidity.com/2024/11/12/supporting-single-item-rss/index.html) RSS are supported, for RSS use-cases beyond notification or syndication of recent posts.

**Some example blogs**

* d24n.org (the first!) \[[source](https://github.com/d24n/d24n-unstatic)\]
* drafts.interfluidity.com \[[source](https://github.com/swaldman/drafts.interfluidity.com)\]
* tech.interfluidity.com \[[source](https://github.com/swaldman/tech.interfluidity.com)\]

(For examples of the fancy revision history stuff, try e.g. [here](https://tech.interfluidity.com/2024/06/06/neonix/index.html) or [here](https://drafts.interfluidity.com/2024/07/03/no-longer-a-liberal-democracy/index.html). Check out the very top and bottom of the posts.)

</div>

---

### 3. Feedletter

**Status:** <span style="color: green; font-weight: bold">Complete</span> (though subject continuing maintenance and improvement)

<div style="margin-left: 1em; border-left: 2px solid orange; padding-left: 1em">

_feedletter_ is a general purpose subscription and notification engine for anything that emits RSS. Full-content RSS feeds can be turned into newsletters, or site digests (bundling multiple articles into more occasional mails). In addition to supporting subscriptions by e-mail, _feedletter_ can send customizable notifications via Mastodon and BlueSky (and can be extended to other channels).

_feedletter_ offers a web API by which users can self-subscribe, generates confirmation e-mails to prevent harrassing 3rd party subscriptions, and provides for one-click unsubscription.

Since RSS feeds can be flaky and send duplicate notifications, _feedletter_ is very careful to retain a records of every item it has already notified, to prevent subscribers and notification channels from being spammed.

E-mail newsletters and digests are designed and formatted as [untemplates](#1-Untemplate) that deployers can design and style.

The _feedletter_ service launches via [mill-daemon](https://github.com/swaldman/mill-daemon), so untemplates can be quickly restyled, and then get automatically recompiled and deployed on restart.

* [Feedletter tutorial](https://tech.interfluidity.com/2024/01/29/feedletter-tutorial/index.html)
* [Source code](https://github.com/swaldman/feedletter)

See the [subscribe page](https://drafts.interfluidity.com/subscribe.html) on drafts.interfluidity.com for some examples.

</div>

---

### 4. Protopost (tentative name)

**Status:** <span style="background-color: black; color: #FFFF00; font-weight: bold">Under development</span> (See protopost.test.mchange.com)
**Estimated Work:** 100 hours


<div style="margin-left: 1em; border-left: 2px solid orange; padding-left: 1em">

_unstatic_ sites, and in particular "simple" blogs are not in fact simple enough for most internet users to build for themselves.

Once built, the "static-site generator" workflow is not friendly to less technical users. It typically requires writing a specially formatted text file for each post, regenerating the site, and uploading the site by some means to the webserver which will serve the static files.

_protopost_ is intended to be a bridge between "user-friendly" posting styles and the technical virtues of static sites. _protopost_ will be a [CMS](https://en.wikipedia.org/wiki/Content_management_system)-style webservice, by which users can compose, revise, and update posts they wish to publish inside a web browser. As with a CMS system, those posts would be stored in a traditional database.

Unlike a traditional CMS system, however, _readers_ would not hit the database system. On publication of a new post (or revision of an old one), regeneration of a static site would be automatically triggered.

From a users' perspective, the advantage of this is permanence, portability, and performance. Webservers know how to deliver static files vey efficiently to clients. When an ordinary user uses a CMS-based publication system, they are entirely dependent upon whoever hosts and maintains the CMS. If the CMS goes dark, so does their work. With _protopost_, users will be able to download their own static site and rehost it at any time. If they wish and they are willing to develop some modest technical proficiency, they can download the _unstatic_ static-site generator, and continue to update and publish their site _unstatic_ style, even after their CMS host has disappeared. If they published under their own custom domain, none of their links need break when they move from a CMS host.

(From a developers' perspective &mdash; well, this developer's perspective &mdash; the _CMS &rArr; static site_ architecture permits building upon all the prior elements of this roadmap, rather than starting fresh to build yet-another-Wordpress-like-thing.)

</div>

### 5. Seismic (tentative name)

**Status:** <span style="background-color: black; color: #FFFF00; font-weight: bold">Under development</span>
**Estimated Work:** 100 hours

<div style="margin-left: 1em; border-left: 2px solid orange; padding-left: 1em">

Seismic is a play on "static-site manager". It would be a daemon-style server application whose role would be to automatically update and regenerate any of many static sites that would be under its jurisdiction.

This is quite at variance with the usual workflow of a static-site generated website, in which humans edit source files and regenerate the site. But thanks to the magic of `git` and similar, the two workflows can be very compatible. The "source code" of a static site can be thought of as a collaborative project between `seismic` and manual authors. Manual authors should get in the habit of re-pulling their own copy of the site source code before editing, just as people who work on collaborative open source projects work to ensure that their copy is up to date. (`seismic` of course does the same!)

The primary anticipated roles of `seismic`, initially, are

1. accepting posts published via [`protopost`](#4-Protopost-tentative-name0)
2. ~~subscribing to RSS of potential commenters, and then transcribing comments into the static site from subscribed sites. (See [Appendix: Cross-site commenting](#Appendix-Cross-site-commenting))~~ (This functionality has been moved to [`protopost`](#4-Protopost-tentative-name0))

It's easy to imagine other applications, such as automatically updating blogrolls with short post summaries, or pluggable themes so that the look and feel of sites can be swapped out on a rebuild. But from-web posting and cross-site comments are the priority for now.
</div>

---

### 6. Paid support or subscriptions

**Status:** <span style="background-color: black; color: #FF0000; font-weight: bold">Not begun</span>
**Estimated Work:** 100 hours

<div style="margin-left: 1em; border-left: 2px solid orange; padding-left: 1em">

None of what's described above involves a paywall. The existing model of reader-supported writing typically relies on a paywall to encourage subscription. There are, however, plenty of financially successful writers who paywall none or very little of their work, and simply request that those who can afford to become paid subscribers to support the work. This is the model I'd try to implement first.

However, rather than (or perhaps as an alternative to) a fixed subscription rate, subscriptions would publish a *maximum* monthly rate, but get billed each month something less than that. Authors would set an aspirational cap &mdash; the amount of money they'd like to make, and amount they believe would leave them generously but fairly compensated for the work that they do. As the number of subscribers grows, rather than author revenue growing linearly, it should grow asymptotically towards that cap. When there are very few aubscribers, each would pay the published maximum monthly rate. As subscribership grows, each subscriber would pay less, as determine by the sublinear path of the asymptotic function. When there are very many subscribers, each subscriber pays a negligible amount but the author receives her full cap.

This reproduces the subscription part of the business model of traditional newspaper and magazine journalism, where each subscriber pays a very small fraction of any staff jouranlist's salary, but purchases access to the work of all of the journalists, because each journalist's salary is amortized over so many subscribers.

I think this model is superior to simple fixed-price subscriptions:

_**From subscribers' perspective**_ — It's cheaper. A subscriber can support more authors for the same budget, and/or just spend less money.

_**From authors' perspective**_ — There are two big benefits for authors:
1. An author has greater justification for the unpleasant, irredeemably annoying, task of soliciting financial support. With a fixed subscription price, authors are asking only for themselves. With a declining subscription price, authors are asking on behalf of their community of readers, asking new subscribers to do their part to make it cheaper for everyone.
2. The declining per-subscription financial take helps an author to purchase intellectual independence from her subscriber base. A big danger of the subscription-supported content model is _audience capture_, whereunder authors find themselves writing to flatter the priors and prejudices of their readers while avoiding ideas and perspectives that might challenge or even anger their audience. It is inevitable, normal, and right that people have strong views and values, and if they find an author's work to deeply violate those values, some will express their dissatisfaction by unsubscribing or boycotting. But writing is a domain in which we want to sustain space for controversial ideas, and where in particular we don't want the communities that each author defines to become echo chambers rather than sites for open, sometimes difficult, deliberation. The declining per-user take means that an author with a large following does not suffer very much financially from unsubscriptions at the margin, as long as they maintain the respect of their broader subscriber base.


(For a description of these ideas in an earlier form, see [_Writing as a public good_](https://www.interfluidity.com/v2/8511.html).)

</div>

---

### Appendix: Cross-site commenting


<div style="margin-left: 1em; border-left: 2px solid orange; padding-left: 1em">

A long-time goal of the [indieweb](https://indieweb.org/) movement has been to enable cross-site conversation and commenting, rather than relying on a single-site or platform to host conversations. When conversations are hosted by a platform, the platform owner can censor, shape traffic with an algorithm, etc. If the platform goes down, so too do the conversations.

The current [indieweb recommendation](https://indieweb.org/comments) for managing cross-site comments involves utilizing [webmention](https://indieweb.org/Webmention) and HTML annotated as commentary via [microformats2](https://indieweb.org/microformats2). _webmention_ is a modernized successor to [trackbacks and pingbacks](https://wordpress.org/documentation/article/trackbacks-and-pingbacks/).

In the old blogosphere, trackbacks and pingbacks were unfortunately often overwhelmingly spam.
The original model, in those halcyon days, was openness. If someone notified your site they
had a comment on your post, your site automatically accepted that, linked to it or even
exceprted from it, under an assumption of trust. Unfortunately, experience has rendered this
assumption unsustainable.

My (opinionated) proposal is the following:

1. Adopt an opt-in model between publishers and potential commenters. If Alice would like
   her responses to Bob's posts to appear upon (or just be linked from) Bob's site, Alice
   gets in touch with Bob and asks that his site should subscribe to her RSS feed, and watch
   for her commentary. This basically eliminates the spam problem, as Bob would not subscribe
   to (or would quickly unsubscribe from) a publisher whose "commentary" was crap.
2. Use RSS, rather than microformats, as the source of information and comment. RSS can be
   annotated (using _iffy_ extensions) as [in-reply-to](https://tech.interfluidity.com/xml/iffy/index.html#iffy-in-reply-to)
   a third party's post. If that third party subscribes, they filter for replies to their
   own work, and update their site to include links to or transcriptions of comments.

This is a very different model than the old blogosphere, under which users with no site of
their own, having made no contact with a blog's publisher, could add their own comments. I
think that model was not great, not just because it was so susceptible to spam, but also
because it created a kind of hierarchy of texts and writers, with "headline" authors
literally at the top, and a mix of commenters ranging from anonymous trolls to impersonators
to accurately self-identified writers themselves highly regarded. The fact that comments were
literally underneath someone else's work, hidden from the majority of readers, often not
attached in any meaningful way to the commenter's reputation, could encourage intemperate
and not-so-interesting responses.

However, the model I propose has potentially worse problems! In particular, the
barrier-to-entry to commenting is much, much higher. On the one hand, that may encourage
a kind of excellence, as writers really devoted to a domain or to one another's work might
converse very richly. On the other hand, it might be undesirably exclusive.

So, I propose that blogs should make it easy for readers to become bloggers themselves! Rather
than advising a long-winded commenter, "hey, have you thought about getting your own blog?",
bloggers might offer, via tools like [protopost](#4-Protopost-tentative-name0), to generate
and host a blog for a commenter who has none. This should not necessarily be a permanent
relationship! Those blogs should be portable, so that the new blogger can be encouraged move
to a more reliable host as they (hopefully!) branch beyond mere commentary on the host's posts.
Or bloggers might not offer this themselves, but point commenters to someone who would host a
blog for them that supports commenting, and agree to subscribe to bring in their comments.

The end goals of this are...

1. Blog commenting should be a "gateway drug" to people having their own, porably hostable,
   inter-commentable blog, helping to build back the muscle of truly decentralizing conversing
   that has been overtaken now by forums like Twitter and Facebook or even Mastodon and Bluesky.
   As long as blogs are portable and resilient, everybody "owns" their own work in a way no
   platform can provide.
2. Since people post under a feed they own, attached to their name or persistent pseudonym,
   there might be some reputational incentive to interact thoughfully and civilly.
3. The distinction in prominence and prestige between "headline poster" and commenter should
   be undermined. A "republic of letters" is made of correspondence between equals (or at least
   people who are structurally equal, even if reputation distinguishes them).

</div>
