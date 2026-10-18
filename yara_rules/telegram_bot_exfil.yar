/*
    A Telegram bot used as the exfiltration channel: the Bot API host and path
    prefix embedded in the DEX together with a send/poll method.

    EVIDENCE BASE: NINE SAMPLES over seven certificates, all measured.
      dceebf2c  com.skqfigg.andgos          "INDUSIND CREDIT CARD"  17/74  2026-07-05  cert 26B02D23
      0c4cd923  com.phantomdroid            "System Update"          2/75  2026-08-22  cert 17876528
      2124956a  com.discord.evs.generator   "Discord EVS Generator"  0/75  2026-08-26  cert 9C1CCF42
      61af1499  com.Sam.RtoEchallan         "PNB HRMS VERIFICATION" 27/75  2026-09-08  cert 26B02D23
      f898162f  cosmos.scrubber.pupil       "AFIP"                  18/75  2026-09-14  cert 91982384
      e7e46ccb  com.example.latest          "RTO e-Challan"         10/74  2026-09-15  cert 684B4301
      aa0dd1d8  (manifest did not parse)                             7/74  2026-09-19  cert 927CA449
      1a150613  (manifest did not parse)                             3/74  2026-09-19  cert 927CA449
      ee87b4c5  banter.afterglow.unfrosted  "Play Store"            34/75  2026-09-28  cert 62B4D922

    The lure names place most of this in one campaign - Indian government and
    bank services (RTO e-Challan, PNB HRMS, IndusInd) plus the Argentine tax
    agency (AFIP). Two certificates are reused across two samples each
    (26B02D23, 927CA449); the remaining five are one-offs.

    WHAT CHANGES AND WHAT DOES NOT:
      changes       the package (nine different, two unparsable), the
                    certificate (seven different), the lure label, the bot
                    token, the chat id, and WHICH Bot API method is called,
      does NOT      the host-and-path prefix "api.telegram.org/bot" - present
                    in 9 of 9 - and the fact that at least one send-or-poll
                    method accompanies it - also 9 of 9.

    THIS RULE DETECTS A CAPABILITY, NOT A FAMILY. A hardcoded bot token is a
    data channel that needs no server of its own, so unrelated operators reach
    for it independently. The seven certificates say as much. Treat a hit as
    "this app talks to a Telegram bot it owns", then look at the lure.

    ANCHORS REJECTED, with the measurement. Control set: the 55 samples in
    output/threat_intel.db that carry a telegram IOC but NOT a Bot API URL -
    i.e. precisely the clean population the README warns about.
      * "telegram.org" on its own - 38 of 55 controls. Already rejected once
        in this repo for the same reason: it is an artefact of the Telegram
        client source and of apps that merely link to a channel. Kept here
        only as a comment, never as a string.
      * "chat_id=" on its own - 8 of 55 controls, every one of them a Telegram
        client fork (Nagram, AyuGram, Oniongram, exteraless). Unusable alone,
        and it adds nothing next to "/sendMessage", which already contains it
        in the 7 samples that use that method.
      * The literal bot token. Only 3 of the 9 samples carry a full
        "bot<digits>:<token>" literal (7779906180 twice, 8661474382 once); the
        other 6 assemble the URL at runtime from a format string, so a rule
        requiring the token would miss two thirds of the cluster. The tokens
        stay in the database as IOCs.
      * A specific bot id as the operator anchor. The best one covers 2
        samples (7779906180: f898162f and ee87b4c5) and dies the moment the
        operator rotates the token in BotFather. Too narrow and too perishable.

    SCANNER PASS: content only. All strings were measured inside the
    concatenated decompressed entries, i.e. what rules.match(data=...) sees -
    they live in classes.dex. Measured as ASCII in 9 of 9 and as UTF-16 in
    0 of 9, so there is deliberately no "wide" modifier here: adding one would
    be noise. A build using the ZIP tricks from venom_tools.yar or
    metamask_loader.yar empties that buffer and silences this rule, as it does
    any content-pass rule.
*/

rule Telegram_Bot_Exfil_Channel
{
    meta:
        description = "Telegram Bot API used as a C2 or exfiltration channel: api.telegram.org/bot plus a send or poll method in the DEX"
        family = "generic capability - not a single family"
        campaign_hint = "majority are Indian gov/bank lures: RTO e-Challan, PNB HRMS, IndusInd"
        samples_seen = 9
        distinct_certs = 7
        vt_range = "0-34 / 75"
        first_seen = "2026-07"
        false_positives = "0 of 55 telegram-bearing controls; see the header for the rejected anchors"
    strings:
        // Host AND path prefix together. The bare host would also match the
        // official client; "/bot" is what makes it a bot endpoint. No token
        // and no wide modifier - both measured, see the header.
        $bot = "api.telegram.org/bot" ascii

        // The method decides direction. Any ONE of these next to $bot means
        // the bot is being used as a channel rather than linked to.
        $send = "/sendMessage" ascii      // 7 of 9
        $doc = "/sendDocument" ascii      // 3 of 9 - file theft
        $photo = "/sendPhoto" ascii       // 2 of 9 - screenshots
        $poll = "/getUpdates" ascii       // 1 of 9 - inbound commands, i.e. C2
    condition:
        // Deliberately 1-of and not more: the method set varies per build and
        // three samples carry exactly one. dceebf2c has only $photo and
        // 2124956a has only $doc, so any higher threshold loses them.
        $bot and 1 of ($send, $doc, $photo, $poll)
}
