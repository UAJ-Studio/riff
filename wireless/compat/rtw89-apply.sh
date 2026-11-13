#!/bin/bash
# Replace the backports tree's rtw89 with a newer one (USB: 8852AU/8852CU/8922AU)
# and adapt it to the 6.18 mac80211 of the base backports. From WiFiCap.
# usage: rtw89-apply.sh <backports tree> <newer backports or kernel tree>
set -euo pipefail
K=$1; M=$2
HERE=$(cd "$(dirname "$0")" && pwd)
R=$K/drivers/net/wireless/realtek/rtw89

rm -rf "$R"
cp -r "$M/drivers/net/wireless/realtek/rtw89" "$R"
cp "$HERE/rtw89-compat.h" "$R/wificap-compat.h"
sed -i '1a ccflags-y += -include $(src)/wificap-compat.h' "$R/Makefile"

# 6.18 mac80211 has no RX_FLAG_RADIOTAP_VHT: skip driver-built VHT radiotap.
sed -i '/^static void rtw89_core_update_radiotap_vht(/,/^}/ s/if (!phy_ppdu)/if (1 || !phy_ppdu)/' "$R/core.c"
grep -q 'if (1 || !phy_ppdu)' "$R/core.c" || { echo "VHT radiotap patch failed"; exit 1; }

# Backport __ieee80211_iterate_stations() (used by for_each_station()).
U=$K/net/mac80211/util.c
H=$K/include/net/mac80211.h
if ! grep -q '__ieee80211_iterate_stations' "$H"; then
    sed -i '0,/^void ieee80211_iterate_stations_mtx(/s//struct ieee80211_sta *\n__ieee80211_iterate_stations(struct ieee80211_hw *hw,\n\t\t\t     struct ieee80211_sta *prev);\n\n&/' "$H"
fi
if ! grep -q '__ieee80211_iterate_stations' "$U"; then
    cat >> "$U" <<'EOF'

/* wificap: backported from mainline for rtw89 for_each_station() */
struct ieee80211_sta *
__ieee80211_iterate_stations(struct ieee80211_hw *hw,
			     struct ieee80211_sta *prev)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct sta_info *sta = NULL;

	lockdep_assert_wiphy(local->hw.wiphy);

	if (prev)
		sta = container_of(prev, struct sta_info, sta);

	sta = list_prepare_entry(sta, &local->sta_list, list);
	list_for_each_entry_continue(sta, &local->sta_list, list) {
		if (!sta->uploaded)
			continue;

		return &sta->sta;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(__ieee80211_iterate_stations);
EOF
fi
echo "BACKPORT_OK"
