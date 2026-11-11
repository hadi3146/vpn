package com.aethervpn.client.data.datastore

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.aethervpn.vpncore.transport.SniStrategy
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "aether_vpn_settings")

enum class DnsMode(val id: Int) {
    VPN_DEFAULT(0),
    DOT_OVER_SSTP(1),
    DNS_ONLY(2);

    companion object {
        fun fromId(id: Int): DnsMode = entries.firstOrNull { it.id == id } ?: VPN_DEFAULT
    }
}

enum class SplitTunnelMode(val id: Int) {
    ALL_APPS(0),
    ALLOWED_ONLY(1),
    DISALLOWED_ONLY(2);

    companion object {
        fun fromId(id: Int): SplitTunnelMode = entries.firstOrNull { it.id == id } ?: ALL_APPS
    }
}

data class UserSettings(
    val strictCert: Boolean = false,
    val dnsMode: DnsMode = DnsMode.VPN_DEFAULT,
    val selectedDnsId: String = "cloudflare",
    val sniStrategy: SniStrategy = SniStrategy.DIRECT_IP_NO_SNI,
    val customSni: String = "",
    val mtu: Int = 1400,
    val keepaliveSec: Int = 30,
    val killSwitch: Boolean = false,
    val autoConnectBoot: Boolean = false,
    val splitTunnelMode: SplitTunnelMode = SplitTunnelMode.ALL_APPS,
    val allowedPackages: Set<String> = emptySet(),
    val disallowedPackages: Set<String> = emptySet(),
    val mirrorUrls: String = "https://www.vpngate.net/api/iphone/\nhttp://www.vpngate.net/api/iphone/",
    val appLanguage: String = "system"
)

class PreferencesManager(private val context: Context) {

    private object Keys {
        val STRICT_CERT = booleanPreferencesKey("strict_cert")
        val DNS_MODE = intPreferencesKey("dns_mode")
        val SELECTED_DNS_ID = stringPreferencesKey("selected_dns_id")
        val SNI_STRATEGY = intPreferencesKey("sni_strategy")
        val CUSTOM_SNI = stringPreferencesKey("custom_sni")
        val MTU = intPreferencesKey("mtu")
        val KEEPALIVE_SEC = intPreferencesKey("keepalive_sec")
        val KILL_SWITCH = booleanPreferencesKey("kill_switch")
        val AUTO_CONNECT_BOOT = booleanPreferencesKey("auto_connect_boot")
        val SPLIT_TUNNEL_MODE = intPreferencesKey("split_tunnel_mode")
        val ALLOWED_PACKAGES = stringSetPreferencesKey("allowed_packages")
        val DISALLOWED_PACKAGES = stringSetPreferencesKey("disallowed_packages")
        val MIRROR_URLS = stringPreferencesKey("mirror_urls")
        val APP_LANGUAGE = stringPreferencesKey("app_language")
    }

    val settingsFlow: Flow<UserSettings> = context.dataStore.data.map { pref ->
        UserSettings(
            strictCert = pref[Keys.STRICT_CERT] ?: false,
            dnsMode = DnsMode.fromId(pref[Keys.DNS_MODE] ?: 0),
            selectedDnsId = pref[Keys.SELECTED_DNS_ID] ?: "cloudflare",
            sniStrategy = SniStrategy.fromId(pref[Keys.SNI_STRATEGY] ?: SniStrategy.DIRECT_IP_NO_SNI.id),
            customSni = pref[Keys.CUSTOM_SNI] ?: "",
            mtu = pref[Keys.MTU] ?: 1400,
            keepaliveSec = pref[Keys.KEEPALIVE_SEC] ?: 30,
            killSwitch = pref[Keys.KILL_SWITCH] ?: false,
            autoConnectBoot = pref[Keys.AUTO_CONNECT_BOOT] ?: false,
            splitTunnelMode = SplitTunnelMode.fromId(pref[Keys.SPLIT_TUNNEL_MODE] ?: 0),
            allowedPackages = pref[Keys.ALLOWED_PACKAGES] ?: emptySet(),
            disallowedPackages = pref[Keys.DISALLOWED_PACKAGES] ?: emptySet(),
            mirrorUrls = pref[Keys.MIRROR_URLS] ?: "https://www.vpngate.net/api/iphone/",
            appLanguage = pref[Keys.APP_LANGUAGE] ?: "system"
        )
    }

    suspend fun updateStrictCert(enabled: Boolean) {
        context.dataStore.edit { it[Keys.STRICT_CERT] = enabled }
    }

    suspend fun updateDnsMode(mode: DnsMode) {
        context.dataStore.edit { it[Keys.DNS_MODE] = mode.id }
    }

    suspend fun updateSelectedDnsId(dnsId: String) {
        context.dataStore.edit { it[Keys.SELECTED_DNS_ID] = dnsId }
    }

    suspend fun updateSniStrategy(strategy: SniStrategy) {
        context.dataStore.edit { it[Keys.SNI_STRATEGY] = strategy.id }
    }

    suspend fun updateCustomSni(sni: String) {
        context.dataStore.edit { it[Keys.CUSTOM_SNI] = sni }
    }

    suspend fun updateMtu(mtu: Int) {
        context.dataStore.edit { it[Keys.MTU] = mtu }
    }

    suspend fun updateKeepalive(seconds: Int) {
        context.dataStore.edit { it[Keys.KEEPALIVE_SEC] = seconds }
    }

    suspend fun updateKillSwitch(enabled: Boolean) {
        context.dataStore.edit { it[Keys.KILL_SWITCH] = enabled }
    }

    suspend fun updateAutoConnectBoot(enabled: Boolean) {
        context.dataStore.edit { it[Keys.AUTO_CONNECT_BOOT] = enabled }
    }

    suspend fun updateSplitTunnelMode(mode: SplitTunnelMode) {
        context.dataStore.edit { it[Keys.SPLIT_TUNNEL_MODE] = mode.id }
    }

    suspend fun updateAllowedPackages(packages: Set<String>) {
        context.dataStore.edit { it[Keys.ALLOWED_PACKAGES] = packages }
    }

    suspend fun updateDisallowedPackages(packages: Set<String>) {
        context.dataStore.edit { it[Keys.DISALLOWED_PACKAGES] = packages }
    }

    suspend fun updateMirrorUrls(urls: String) {
        context.dataStore.edit { it[Keys.MIRROR_URLS] = urls }
    }

    suspend fun updateLanguage(lang: String) {
        context.dataStore.edit { it[Keys.APP_LANGUAGE] = lang }
    }
}

