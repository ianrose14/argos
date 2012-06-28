#ifndef CLICK_CHECKWIFI_HH
#define CLICK_CHECKWIFI_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c
CheckWifi()

=s Argos

*/

class CheckWifi : public Element {
public:
    CheckWifi();
    ~CheckWifi();

    const char *class_name() const	{ return "CheckWifi"; }
    const char *port_count() const	{ return PORTS_1_1X2; }
    const char *processing() const      { return PROCESSING_A_AH; }

    void add_handlers();
    int configure(Vector<String>&, ErrorHandler*);
    Packet *simple_action(Packet*);

private:
    bool validate_assocreq(const struct ieee80211_frame*, size_t) const;
    bool validate_assocresp(const struct ieee80211_frame*, size_t) const;
    bool validate_auth(const struct ieee80211_frame*, size_t) const;
    bool validate_beacon(const struct ieee80211_frame*, size_t) const;
    bool validate_cipher_elts(const u_char*, size_t) const;
    bool validate_deauth(const struct ieee80211_frame*, size_t) const;
    bool validate_disassoc(const struct ieee80211_frame*, size_t) const;
    bool validate_probereq(const struct ieee80211_frame*, size_t) const;
    bool validate_proberesp(const struct ieee80211_frame*, size_t) const;
    bool validate_reassocreq(const struct ieee80211_frame*, size_t) const;
    bool validate_reassocresp(const struct ieee80211_frame*, size_t) const;

    static String read_handler(Element*, void*);
    static int write_handler(const String&, Element*, void*, ErrorHandler*);

    uint32_t _drops;
    bool _verbose;
};

CLICK_ENDDECLS
#endif
