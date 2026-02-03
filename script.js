/**
 * WhatsApp Traffic Manipulator v3 — Full Suite
 * 
 * Based on Baileys WABinary decoder + encoder.
 * Hooks crypto.subtle.encrypt/decrypt to intercept Noise transport frames.
 * 
 * FEATURES (all operate at transport layer, NOT E2E):
 *   1. Read Receipt Blocker  — hide blue ticks from others
 *   2. Played Receipt Blocker — hide voice note "played" status
 *   3. Typing Indicator Blocker — hide "typing..." from others
 *   4. Online Presence Hider — appear offline while browsing
 *   5. Anti-Delete Detector — alert when someone deletes a message
 *   6. Delivery Receipt Blocker — hide grey double-check from others
 *   7. Recording Indicator Blocker — hide "recording..." from others
 *
 * COMMANDS:
 *   blockReads() / allowReads()     — read receipts (default: ON)
 *   blockPlayed() / allowPlayed()   — played receipts (default: OFF)
 *   blockTyping() / allowTyping()   — typing indicators (default: OFF)
 *   goGhost() / goVisible()         — online presence (default: OFF)
 *   blockDelivery() / allowDelivery() — delivery receipts (default: OFF)
 *   blockRecording() / allowRecording() — recording indicator (default: OFF)
 *   showBlocked()                   — list all blocked items
 *   showDeleted()                   — list detected message deletions
 *   showTraffic(N)                  — show last N frames
 *   filterTraffic("keyword")       — filter frames
 *   status()                        — show what's enabled/disabled
 */
(function() {
    'use strict';
    console.log('%c🔒 WhatsApp Traffic Manipulator v3', 'color: #f44; font-size: 18px; font-weight: bold');

    // =============================================
    // Token Tables (from Baileys constants.ts)
    // =============================================
    const SINGLE_BYTE_TOKENS = [
        '', 'xmlstreamstart', 'xmlstreamend', 's.whatsapp.net', 'type',
        'participant', 'from', 'receipt', 'id', 'notification',
        'disappearing_mode', 'status', 'jid', 'broadcast', 'user',
        'devices', 'device_hash', 'to', 'offline', 'message',
        'result', 'class', 'xmlns', 'duration', 'notify',
        'iq', 't', 'ack', 'g.us', 'enc',
        'urn:xmpp:whatsapp:push', 'presence', 'config_value', 'picture', 'verified_name',
        'config_code', 'key-index-list', 'contact', 'mediatype', 'routing_info',
        'edge_routing', 'get', 'read', 'urn:xmpp:ping', 'fallback_hostname',
        '0', 'chatstate', 'business_hours_config', 'unavailable', 'download_buckets',
        'skmsg', 'verified_level', 'composing', 'handshake', 'device-list',
        'media', 'text', 'fallback_ip4', 'media_conn', 'device',
        'creation', 'location', 'config', 'item', 'fallback_ip6',
        'count', 'w:profile:picture', 'image', 'business', '2',
        'hostname', 'call-creator', 'display_name', 'relaylatency', 'platform',
        'abprops', 'success', 'msg', 'offline_preview', 'prop',
        'key-index', 'v', 'day_of_week', 'pkmsg', 'version',
        '1', 'ping', 'w:p', 'download', 'video',
        'set', 'specific_hours', 'props', 'primary', 'unknown',
        'hash', 'commerce_experience', 'last', 'subscribe', 'max_buckets',
        'call', 'profile', 'member_since_text', 'close_time', 'call-id',
        'sticker', 'mode', 'participants', 'value', 'query',
        'profile_options', 'open_time', 'code', 'list', 'host',
        'ts', 'contacts', 'upload', 'lid', 'preview',
        'update', 'usync', 'w:stats', 'delivery', 'auth_ttl',
        'context', 'fail', 'cart_enabled', 'appdata', 'category',
        'atn', 'direct_connection', 'decrypt-fail', 'relay_id', 'mmg-fallback.whatsapp.net',
        'target', 'available', 'name', 'last_id', 'mmg.whatsapp.net',
        'categories', '401', 'is_new', 'index', 'tctoken',
        'ip4', 'token_id', 'latency', 'recipient', 'edit',
        'ip6', 'add', 'thumbnail-document', '26', 'paused',
        'true', 'identity', 'stream:error', 'key', 'sidelist',
        'background', 'audio', '3', 'thumbnail-image', 'biz-cover-photo',
        'cat', 'gcm', 'thumbnail-video', 'error', 'auth',
        'deny', 'serial', 'in', 'registration', 'thumbnail-link',
        'remove', '00', 'gif', 'thumbnail-gif', 'tag',
        'capability', 'multicast', 'item-not-found', 'description', 'business_hours',
        'config_expo_key', 'md-app-state', 'expiration', 'fallback', 'ttl',
        '300', 'md-msg-hist', 'device_orientation', 'out', 'w:m',
        'open_24h', 'side_list', 'token', 'inactive', '01',
        'document', 'te2', 'played', 'encrypt', 'msgr',
        'hide', 'direct_path', '12', 'state', 'not-authorized',
        'url', 'terminate', 'signature', 'status-revoke-delay', '02',
        'te', 'linked_accounts', 'trusted_contact', 'timezone', 'ptt',
        'kyc-id', 'privacy_token', 'readreceipts', 'appointment_only', 'address',
        'expected_ts', 'privacy', '7', 'android', 'interactive',
        'device-identity', 'enabled', 'attribute_padding', '1080', '03',
        'screen_height'
    ];

    const DOUBLE_BYTE_TOKENS = [
        ['read-self','active','fbns','protocol','reaction','screen_width','heartbeat','deviceid','2:47DEQpj8','uploadfieldstat','voip_settings','retry','priority','longitude','conflict','false','ig_professional','replaced','preaccept','cover_photo','uncompressed','encopt','ppic','04','passive','status-revoke-drop','keygen','540','offer','rate','opus','latitude','w:gp2','ver','4','business_profile','medium','sender','prev_v_id','email','website','invited','sign_credential','05','transport','skey','reason','peer_abtest_bucket','America/Sao_Paulo','appid','refresh','100','06','404','101','104','107','102','109','103','member_add_mode','105','transaction-id','110','106','outgoing','108','111','tokens','followers','ig_handle','self_pid','tue','dec','thu','joinable','peer_pid','mon','features','wed','peer_device_presence','pn','delete','07','fri','audio_duration','admin','connected','delta','rcat','disable','collection','08','480','sat','phash','all','invite','accept','critical_unblock_low','group_update','signed_credential','blinded_credential','eph_setting','net','09','background_location','refresh_id','Asia/Kolkata','privacy_mode_ts','account_sync','voip_payload_type','service_areas','acs_public_key','v_id','0a','fallback_class','relay','actual_actors','metadata','w:biz','5','connected-limit','notice','0b','host_storage','fb_page','subject','privatestats','invis','groupadd','010','note.m4r','uuid','0c','8000','sun','372','1020','stage','1200','720','canonical','fb','011','video_duration','0d','1140','superadmin','012','Opening.m4r','keystore_attestation','dleq_proof','013','timestamp','ab_key','w:sync:app:state','0e','vertical','600','p_v_id','6','likes','014','500','1260','creator','0f','rte','destination','group','group_info','syncd_anti_tampering_fatal_exception_enabled','015','dl_bw','Asia/Jakarta','vp8/h.264','online','1320','fb:multiway','10','timeout','016','nse_retry','urn:xmpp:whatsapp:dirty','017','a_v_id','web_shops_chat_header_button_enabled','nse_call','inactive-upgrade','none','web','groups','2250','mms_hot_content_timespan_in_seconds','contact_blacklist','nse_read','suspended_group_deletion_notification','binary_version','018','https://www.whatsapp.com/otp/copy/','reg_push','shops_hide_catalog_attachment_entrypoint','server_sync','.','ephemeral_messages_allowed_values','019','mms_vcache_aggregation_enabled','iphone','America/Argentina/Buenos_Aires','01a','mms_vcard_autodownload_size_kb','nse_ver','shops_header_dropdown_menu_item','dhash','catalog_status','communities_mvp_new_iqs_serverprop','blocklist','default','11','ephemeral_messages_enabled','01b','original_dimensions','8','mms4_media_retry_notification_encryption_enabled','mms4_server_error_receipt_encryption_enabled','original_image_url','sync','multiway','420','companion_enc_static','shops_profile_drawer_entrypoint','01c','vcard_as_document_size_kb','status_video_max_duration','request_image_url','01d','regular_high','s_t','abt','share_ext_min_preliminary_image_quality','01e','32','syncd_key_rotation_enabled','data_namespace','md_downgrade_read_receipts2','patch','polltype','ephemeral_messages_setting','userrate','15','partial_pjpeg_bw_threshold','played-self','catalog_exists','01f','mute_v2'],
        ['reject','dirty','announcement','020','13','9','status_video_max_bitrate','fb:thrift_iq','offline_batch','022','full','ctwa_first_business_reply_logging','h.264','smax_id','group_description_length','https://www.whatsapp.com/otp/code','status_image_max_edge','smb_upsell_business_profile_enabled','021','web_upgrade_to_md_modal','14','023','s_o','smaller_video_thumbs_status_enabled','media_max_autodownload','960','blocking_status','peer_msg','joinable_group_call_client_version','group_call_video_maximization_enabled','return_snapshot','high','America/Mexico_City','entry_point_block_logging_enabled','pop','024','1050','16','1380','one_tap_calling_in_group_chat_size','regular_low','inline_joinable_education_enabled','hq_image_max_edge','locked','America/Bogota','smb_biztools_deeplink_enabled','status_image_quality','1088','025','payments_upi_intent_transaction_limit','voip','w:g2','027','md_pin_chat_enabled','026','multi_scan_pjpeg_download_enabled','shops_product_grid','transaction_id','ctwa_context_enabled','20','fna','hq_image_quality','alt_jpeg_doc_detection_quality','group_call_max_participants','pkey','America/Belem','image_max_kbytes','web_cart_v1_1_order_message_changes_enabled','ctwa_context_enterprise_enabled','urn:xmpp:whatsapp:account','840','Asia/Kuala_Lumpur','max_participants','video_remux_after_repair_enabled','stella_addressbook_restriction_type','660','900','780','context_menu_ios13_enabled','mute-state','ref','payments_request_messages','029','frskmsg','vcard_max_size_kb','sample_buffer_gif_player_enabled','match_last_seen','510','4983','video_max_bitrate','028','w:comms:chat','17','frequently_forwarded_max','groups_privacy_blacklist','Asia/Karachi','02a','web_download_document_thumb_mms_enabled','02b','hist_sync','biz_block_reasons_version','1024','18','web_is_direct_connection_for_plm_transparent','view_once_write','file_max_size','paid_convo_id','online_privacy_setting','video_max_edge','view_once_read','enhanced_storage_management','multi_scan_pjpeg_encoding_enabled','ctwa_context_forward_enabled','video_transcode_downgrade_enable','template_doc_mime_types','hq_image_bw_threshold','30','body','u_aud_limit_sil_restarts_ctrl','other','participating','w:biz:directory','1110','vp8','4018','meta','doc_detection_image_max_edge','image_quality','1170','02c','smb_upsell_chat_banner_enabled','key_expiry_time_second','pid','stella_interop_enabled','19','linked_device_max_count','md_device_sync_enabled','02d','02e','360','enhanced_block_enabled','ephemeral_icon_in_forwarding','paid_convo_status','gif_provider','project_name','server-error','canonical_url_validation_enabled','wallpapers_v2','syncd_clear_chat_delete_chat_enabled','medianotify','02f','shops_required_tos_version','vote','reset_skey_on_id_change','030','image_max_edge','multicast_limit_global','ul_bw','21','25','5000','poll','570','22','031','1280','WhatsApp','032','bloks_shops_enabled','50','upload_host_switching_enabled','web_ctwa_context_compose_enabled','ptt_forwarded_features_enabled','unblocked','partial_pjpeg_enabled','fbid:devices','height','ephemeral_group_query_ts','group_join_permissions','order','033','alt_jpeg_status_quality','migrate','popular-bank','win_uwp_deprecation_killswitch_enabled','web_download_status_thumb_mms_enabled','blocking','url_text','035','web_forwarding_limit_to_groups','1600','val','1000','syncd_msg_date_enabled','bank-ref-id','max_subject','payments_web_enabled','web_upload_document_thumb_mms_enabled','size','request','ephemeral','24','receipt_agg','ptt_remember_play_position','sampling_weight','enc_rekey','mute_always','037','034','23','036','action','click_to_chat_qr_enabled','width','disabled','038','md_blocklist_v2','played_self_enabled','web_buttons_message_enabled','flow_id','clear','450','fbid:thread','bloks_session_state','America/Lima','attachment_picker_refresh','download_host_switching_enabled','1792','u_aud_limit_sil_restarts_test2','custom_urls','device_fanout','optimistic_upload','2000','key_cipher_suite','web_smb_upsell_in_biz_profile_enabled','e','039','siri_post_status_shortcut','pair-device','lg','lc','stream_attribution_url','model','mspjpeg_phash_gen','catalog_send_all','new_multi_vcards_ui','share_biz_vcard_enabled','-','clean','200','md_blocklist_v2_server','03b','03a','web_md_migration_experience','ptt_conversation_waveform','u_aud_limit_sil_restarts_test1'],
        ['64','ptt_playback_speed_enabled','web_product_list_message_enabled','paid_convo_ts','27','manufacturer','psp-routing','grp_uii_cleanup','ptt_draft_enabled','03c','business_initiated','web_catalog_products_onoff','web_upload_link_thumb_mms_enabled','03e','mediaretry','35','hfm_string_changes','28','America/Fortaleza','max_keys','md_mhfs_days','streaming_upload_chunk_size','5541','040','03d','2675','03f','...','512','mute','48','041','alt_jpeg_quality','60','042','md_smb_quick_reply','5183','c','1343','40','1230','043','044','mms_cat_v1_forward_hot_override_enabled','user_notice','ptt_waveform_send','047','Asia/Calcutta','250','md_privacy_v2','31','29','128','md_messaging_enabled','046','crypto','690','045','enc_iv','75','failure','ptt_oot_playback','AIzaSyDR5yfaG7OG8sMTUj8kfQEb8T9pN8BM6Lk','w','048','2201','web_large_files_ui','Asia/Makassar','812','status_collapse_muted','1334','257','2HP4dm','049','patches','1290','43cY6T','America/Caracas','web_sticker_maker','campaign','ptt_pausable_enabled','33','42','attestation','biz','04b','query_linked','s','125','04a','810','availability','1411','responsiveness_v2_m1','catalog_not_created','34','America/Santiago','1465','enc_p','04d','status_info','04f','key_version','..','04c','04e','md_group_notification','1598','1215','web_cart_enabled','37','630','1920','2394','-1','vcard','38','elapsed','36','828','peer','pricing_category','1245','invalid','stella_ios_enabled','2687','45','1528','39','u_is_redial_audio_1104_ctrl','1025','1455','58','2524','2603','054','bsp_system_message_enabled','web_pip_redesign','051','verify_apps','1974','1272','1322','1755','052','70','050','1063','1135','1361','80','1096','1828','1851','1251','1921','key_config_id','1254','1566','1252','2525','critical_block','1669','max_available','w:auth:backup:token','product','2530','870','1022','participant_uuid','web_cart_on_off','1255','1432','1867','41','1415','1440','240','1204','1608','1690','1846','1483','1687','1749','69','url_number','053','1325','1040','365','59','Asia/Riyadh','1177','test_recommended','057','1612','43','1061','1518','1635','055','1034','1375','750','1430','event_code','1682','503','55','865','78','1309','1365','44','America/Guayaquil','535','LIMITED','1377','1613','1420','1599','1822','05a','1681','password','1111','1214','1376','1478','47','1082','4282','Europe/Istanbul','1307','46','058','1124','256','rate-overlimit','retail','u_a_socket_err_fix_succ_test','1292','1370','1388','520','861','psa','regular','1181','1766','05b','1183','1213','1304','1537'],
        ['1724','profile_picture','1071','1314','1605','407','990','1710','746','pricing_model','056','059','061','1119','6027','65','877','1607','05d','917','seen','1516','49','470','973','1037','1350','1394','1480','1796','keys','794','1536','1594','2378','1333','1524','1825','116','309','52','808','827','909','495','1660','361','957','google','1357','1565','1967','996','1775','586','736','1052','1670','bank','177','1416','2194','2222','1454','1839','1275','53','997','1629','6028','smba','1378','1410','05c','1849','727','create','1559','536','1106','1310','1944','670','1297','1316','1762','en','1148','1295','1551','1853','1890','1208','1784','7200','05f','178','1283','1332','381','643','1056','1238','2024','2387','179','981','1547','1705','05e','290','903','1069','1285','2436','062','251','560','582','719','56','1700','2321','325','448','613','777','791','51','488','902','Asia/Almaty','is_hidden','1398','1527','1893','1999','2367','2642','237','busy','065','067','233','590','993','1511','54','723','860','363','487','522','605','995','1321','1691','1865','2447','2462','NON_TRANSACTIONAL','433','871','432','1004','1207','2032','2050','2379','2446','279','636','703','904','248','370','691','700','1068','1655','2334','060','063','364','533','534','567','1191','1210','1473','1827','069','701','2531','514','prev_dhash','064','496','790','1046','1139','1505','1521','1108','207','544','637','final','1173','1293','1694','1939','1951','1993','2353','2515','504','601','857','modify','spam_request','p_121_aa_1101_test4','866','1427','1502','1638','1744','2153','068','382','725','1704','1864','1990','2003','Asia/Dubai','508','531','1387','1474','1632','2307','2386','819','2014','066','387','1468','1706','2186','2261','471','728','1147','1372','1961']
    ];

    const TAGS = {
        LIST_EMPTY: 0,
        DICTIONARY_0: 236, DICTIONARY_1: 237, DICTIONARY_2: 238, DICTIONARY_3: 239,
        INTEROP_JID: 245, FB_JID: 246, AD_JID: 247,
        LIST_8: 248, LIST_16: 249, JID_PAIR: 250,
        HEX_8: 251, BINARY_8: 252, BINARY_20: 253, BINARY_32: 254, NIBBLE_8: 255,
        PACKED_MAX: 127
    };

    // Build TOKEN_MAP for encoder (string → {dict, index})
    const TOKEN_MAP = {};
    for (let i = 0; i < SINGLE_BYTE_TOKENS.length; i++) {
        if (SINGLE_BYTE_TOKENS[i]) TOKEN_MAP[SINGLE_BYTE_TOKENS[i]] = { index: i };
    }
    for (let d = 0; d < DOUBLE_BYTE_TOKENS.length; d++) {
        for (let j = 0; j < DOUBLE_BYTE_TOKENS[d].length; j++) {
            TOKEN_MAP[DOUBLE_BYTE_TOKENS[d][j]] = { dict: d, index: j };
        }
    }

    // =============================================
    // WABinary Decoder (from Baileys decode.ts)
    // =============================================
    function decodeNode(buffer, indexRef) {
        const checkEOS = (n) => { if (indexRef.index + n > buffer.length) throw new Error('EOS'); };
        const next = () => { const v = buffer[indexRef.index]; indexRef.index++; return v; };
        const readByte = () => { checkEOS(1); return next(); };
        const readBytes = (n) => { checkEOS(n); const v = buffer.slice(indexRef.index, indexRef.index + n); indexRef.index += n; return v; };
        const readStringFromChars = (len) => {
            const b = readBytes(len);
            try { return new TextDecoder('utf-8', { fatal: true }).decode(b); }
            catch(e) { return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join(''); }
        };
        const readInt = (n) => { checkEOS(n); let v = 0; for (let i = 0; i < n; i++) v |= next() << ((n-1-i)*8); return v; };
        const readInt20 = () => { checkEOS(3); return ((next()&15)<<16) + (next()<<8) + next(); };

        const unpackHex = (v) => v < 10 ? String.fromCharCode(48+v) : String.fromCharCode(55+v);
        const unpackNibble = (v) => {
            if (v <= 9) return String.fromCharCode(48+v);
            if (v === 10) return '-'; if (v === 11) return '.'; if (v === 15) return '\0';
            throw new Error('nibble: '+v);
        };
        const unpackByte = (tag, v) => tag === TAGS.NIBBLE_8 ? unpackNibble(v) : unpackHex(v);
        const readPacked8 = (tag) => {
            const sb = readByte(); let val = '';
            for (let i = 0; i < (sb & 127); i++) {
                const c = readByte();
                val += unpackByte(tag, (c & 0xF0) >> 4);
                val += unpackByte(tag, c & 0x0F);
            }
            if (sb >> 7 !== 0) val = val.slice(0, -1);
            return val;
        };

        const isListTag = (t) => t === TAGS.LIST_EMPTY || t === TAGS.LIST_8 || t === TAGS.LIST_16;
        const readListSize = (t) => {
            if (t === TAGS.LIST_EMPTY) return 0;
            if (t === TAGS.LIST_8) return readByte();
            if (t === TAGS.LIST_16) return readInt(2);
            throw new Error('list tag: '+t);
        };

        const readJidPair = () => {
            const i = readString(readByte()), j = readString(readByte());
            if (j) return (i||'') + '@' + j;
            throw new Error('jid pair');
        };
        const readAdJid = () => {
            const dt = readByte(), dev = readByte(), user = readString(readByte());
            let srv = 's.whatsapp.net';
            if (dt === 1) srv = 'lid'; else if (dt === 128) srv = 'hosted'; else if (dt === 129) srv = 'hosted.lid';
            return `${user||''}${dev ? ':'+dev : ''}@${srv}`;
        };
        const readFbJid = () => { const u = readString(readByte()), d = readInt(2), s = readString(readByte()); return `${u}:${d}@${s}`; };
        const readInteropJid = () => {
            const u = readString(readByte()), d = readInt(2), ig = readInt(2);
            let s = 'interop'; const b = indexRef.index;
            try { s = readString(readByte()); } catch(e) { indexRef.index = b; }
            return `${ig}-${u}:${d}@${s}`;
        };

        const getTokenDouble = (ti, i2) => {
            const t = DOUBLE_BYTE_TOKENS[ti];
            return (t && i2 < t.length) ? t[i2] : `[2nd${ti}:${i2}]`;
        };

        const readString = (tag) => {
            if (tag >= 1 && tag < SINGLE_BYTE_TOKENS.length) return SINGLE_BYTE_TOKENS[tag] || '';
            switch (tag) {
                case TAGS.DICTIONARY_0: case TAGS.DICTIONARY_1: case TAGS.DICTIONARY_2: case TAGS.DICTIONARY_3:
                    return getTokenDouble(tag - TAGS.DICTIONARY_0, readByte());
                case TAGS.LIST_EMPTY: return '';
                case TAGS.BINARY_8: return readStringFromChars(readByte());
                case TAGS.BINARY_20: return readStringFromChars(readInt20());
                case TAGS.BINARY_32: return readStringFromChars(readInt(4));
                case TAGS.JID_PAIR: return readJidPair();
                case TAGS.FB_JID: return readFbJid();
                case TAGS.INTEROP_JID: return readInteropJid();
                case TAGS.AD_JID: return readAdJid();
                case TAGS.HEX_8: case TAGS.NIBBLE_8: return readPacked8(tag);
                default: throw new Error('str tag: '+tag);
            }
        };
        const readList = (tag) => {
            const items = [], size = readListSize(tag);
            for (let i = 0; i < size; i++) items.push(decodeNode(buffer, indexRef));
            return items;
        };

        const listSize = readListSize(readByte());
        const header = readString(readByte());
        if (!listSize || !header.length) throw new Error('invalid node');
        const attrs = {};
        for (let i = 0; i < (listSize-1)>>1; i++) {
            attrs[readString(readByte())] = readString(readByte());
        }
        let content;
        if (listSize % 2 === 0) {
            const ct = readByte();
            if (isListTag(ct)) { content = readList(ct); }
            else {
                switch (ct) {
                    case TAGS.BINARY_8: content = readBytes(readByte()); break;
                    case TAGS.BINARY_20: content = readBytes(readInt20()); break;
                    case TAGS.BINARY_32: content = readBytes(readInt(4)); break;
                    default: content = readString(ct); break;
                }
            }
        }
        return { tag: header, attrs, content };
    }

    // =============================================
    // WABinary Encoder (from Baileys encode.ts)
    // =============================================
    function encodeNode(node, buffer) {
        if (!buffer) buffer = [0]; // first byte = 0x00 (uncompressed flag)
        const { tag, attrs, content } = node;

        const pushByte = (v) => buffer.push(v & 0xff);
        const pushInt = (v, n) => { for (let i = 0; i < n; i++) buffer.push((v >> ((n-1-i)*8)) & 0xff); };
        const pushBytes = (bs) => { for (const b of bs) buffer.push(b); };
        const pushInt16 = (v) => pushBytes([(v>>8)&0xff, v&0xff]);
        const pushInt20 = (v) => pushBytes([(v>>16)&0x0f, (v>>8)&0xff, v&0xff]);

        const writeByteLength = (len) => {
            if (len >= 1 << 20) { pushByte(TAGS.BINARY_32); pushInt(len, 4); }
            else if (len >= 256) { pushByte(TAGS.BINARY_20); pushInt20(len); }
            else { pushByte(TAGS.BINARY_8); pushByte(len); }
        };

        const writeStringRaw = (str) => {
            const enc = new TextEncoder();
            const bytes = enc.encode(str);
            writeByteLength(bytes.length);
            pushBytes(bytes);
        };

        const isNibble = (s) => {
            if (!s || s.length > TAGS.PACKED_MAX) return false;
            for (const c of s) { if (!((c>='0'&&c<='9')||c==='-'||c==='.')) return false; }
            return true;
        };
        const isHex = (s) => {
            if (!s || s.length > TAGS.PACKED_MAX) return false;
            for (const c of s) { if (!((c>='0'&&c<='9')||(c>='A'&&c<='F'))) return false; }
            return true;
        };

        const packNibble = (c) => {
            if (c >= '0' && c <= '9') return c.charCodeAt(0) - 48;
            if (c === '-') return 10; if (c === '.') return 11; if (c === '\0') return 15;
            throw new Error('nibble: '+c);
        };
        const packHex = (c) => {
            if (c >= '0' && c <= '9') return c.charCodeAt(0) - 48;
            if (c >= 'A' && c <= 'F') return 10 + c.charCodeAt(0) - 65;
            if (c >= 'a' && c <= 'f') return 10 + c.charCodeAt(0) - 97;
            if (c === '\0') return 15;
            throw new Error('hex: '+c);
        };

        const writePackedBytes = (str, type) => {
            pushByte(type === 'nibble' ? TAGS.NIBBLE_8 : TAGS.HEX_8);
            let rl = Math.ceil(str.length / 2);
            if (str.length % 2 !== 0) rl |= 128;
            pushByte(rl);
            const pf = type === 'nibble' ? packNibble : packHex;
            for (let i = 0; i < Math.floor(str.length/2); i++)
                pushByte((pf(str[2*i]) << 4) | pf(str[2*i+1]));
            if (str.length % 2 !== 0)
                pushByte((pf(str[str.length-1]) << 4) | pf('\0'));
        };

        // JID detection and encoding
        const jidDecode = (s) => {
            if (typeof s !== 'string') return null;
            const at = s.indexOf('@');
            if (at < 0) return null;
            const server = s.substring(at + 1);
            const validServers = ['s.whatsapp.net','g.us','broadcast','call','lid','newsletter','bot','hosted','hosted.lid','c.us'];
            if (!validServers.includes(server)) return null;
            const left = s.substring(0, at);
            const colon = left.indexOf(':');
            if (colon >= 0) {
                const user = left.substring(0, colon);
                const device = parseInt(left.substring(colon + 1));
                let domainType = 0;
                if (server === 'lid') domainType = 1;
                else if (server === 'hosted') domainType = 128;
                else if (server === 'hosted.lid') domainType = 129;
                return { user, device, server, domainType };
            }
            return { user: left, server };
        };

        const writeJid = (jid) => {
            if (typeof jid.device !== 'undefined') {
                pushByte(TAGS.AD_JID);
                pushByte(jid.domainType || 0);
                pushByte(jid.device || 0);
                writeString(jid.user);
            } else {
                pushByte(TAGS.JID_PAIR);
                if (jid.user && jid.user.length) writeString(jid.user);
                else pushByte(TAGS.LIST_EMPTY);
                writeString(jid.server);
            }
        };

        const writeString = (str) => {
            if (str === undefined || str === null) { pushByte(TAGS.LIST_EMPTY); return; }
            if (str === '') { writeStringRaw(str); return; }
            const tok = TOKEN_MAP[str];
            if (tok) {
                if (typeof tok.dict === 'number') pushByte(TAGS.DICTIONARY_0 + tok.dict);
                pushByte(tok.index);
            } else if (isNibble(str)) {
                writePackedBytes(str, 'nibble');
            } else if (isHex(str)) {
                writePackedBytes(str, 'hex');
            } else {
                const jid = jidDecode(str);
                if (jid) writeJid(jid);
                else writeStringRaw(str);
            }
        };

        const writeListStart = (size) => {
            if (size === 0) pushByte(TAGS.LIST_EMPTY);
            else if (size < 256) { pushByte(TAGS.LIST_8); pushByte(size); }
            else { pushByte(TAGS.LIST_16); pushInt16(size); }
        };

        // --- Encode the node ---
        const validAttrs = Object.keys(attrs || {}).filter(k => attrs[k] !== undefined && attrs[k] !== null);
        writeListStart(2 * validAttrs.length + 1 + (content !== undefined ? 1 : 0));
        writeString(tag);
        for (const key of validAttrs) {
            writeString(key);
            writeString(attrs[key]);
        }
        if (typeof content === 'string') {
            writeString(content);
        } else if (content instanceof Uint8Array) {
            writeByteLength(content.length);
            pushBytes(content);
        } else if (Array.isArray(content)) {
            const valid = content.filter(c => c && c.tag);
            writeListStart(valid.length);
            for (const child of valid) encodeNode(child, buffer);
        }

        return new Uint8Array(buffer);
    }

    // =============================================
    // Pretty-print
    // =============================================
    function prettyNode(node, indent) {
        if (!indent) indent = 0;
        if (!node?.tag) return '';
        const pad = '  '.repeat(indent);
        let out = `${pad}<${node.tag}`;
        for (const [k, v] of Object.entries(node.attrs || {})) out += ` ${k}="${v}"`;
        if (node.content == null || node.content === undefined) {
            out += ' />';
        } else if (Array.isArray(node.content) && node.content[0]?.tag) {
            out += '>';
            for (const c of node.content) out += '\n' + prettyNode(c, indent+1);
            out += `\n${pad}</${node.tag}>`;
        } else if (node.content instanceof Uint8Array) {
            out += `>[bin ${node.content.length}B]</${node.tag}>`;
        } else {
            const s = String(node.content);
            out += `>${s.length > 120 ? s.substring(0,120)+'...' : s}</${node.tag}>`;
        }
        return out;
    }

    // =============================================
    // Frame decode/encode helpers
    // =============================================
    function decodeFrame(rawBytes) {
        const bytes = rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(rawBytes);
        if (bytes.length < 3) return null;
        try {
            // First byte = flag, skip it (uncompressed)
            if (!(bytes[0] & 2)) {
                const ref = { index: 0 };
                return decodeNode(bytes.slice(1), ref);
            }
        } catch(e) {}
        try { const ref = { index: 0 }; return decodeNode(bytes, ref); } catch(e) {}
        return null;
    }

    function encodeFrame(node) {
        return encodeNode(node);
    }

    // =============================================
    // Feature Flags
    // =============================================
    const flags = {
        blockReads:     true,   // blue ticks
        blockPlayed:    false,  // voice note played
        blockTyping:    false,  // typing indicator
        ghostMode:      false,  // online presence
        blockDelivery:  false,  // grey double-check
        blockRecording: false,  // recording audio indicator
    };
    window.__WA_FLAGS = flags;

    // =============================================
    // Logs
    // =============================================
    const blockedLog = [];
    const deletedLog = [];
    const traffic = [];
    window.__WA_BLOCKED = blockedLog;
    window.__WA_DELETED = deletedLog;
    window.__WA_TRAFFIC = traffic;

    // =============================================
    // Frame Classifiers
    // =============================================

    // 1. Read receipts: <receipt type="read" ...> or <ack class="receipt" type="read" ...>
    function isReadReceipt(node) {
        if (!node) return false;
        if (node.tag === 'receipt' && node.attrs.type === 'read') return true;
        if (node.tag === 'ack' && node.attrs.class === 'receipt' && node.attrs.type === 'read') return true;
        return false;
    }

    // 2. Played receipts: <receipt type="played" ...> or <ack class="receipt" type="played" ...>
    function isPlayedReceipt(node) {
        if (!node) return false;
        if (node.tag === 'receipt' && node.attrs.type === 'played') return true;
        if (node.tag === 'ack' && node.attrs.class === 'receipt' && node.attrs.type === 'played') return true;
        return false;
    }

    // 3. Typing indicator: <chatstate to="..."><composing /></chatstate>
    //    Also catches paused: <chatstate to="..."><paused /></chatstate>
    function isTypingIndicator(node) {
        if (!node || node.tag !== 'chatstate') return false;
        if (!Array.isArray(node.content)) return false;
        return node.content.some(c => c.tag === 'composing' || c.tag === 'paused');
    }

    // 4. Online presence: <presence type="available" name="..." />
    function isPresenceAvailable(node) {
        if (!node || node.tag !== 'presence') return false;
        return node.attrs.type === 'available' || node.attrs.type === 'unavailable';
    }

    // 5. Anti-delete: incoming <message ... edit="7"> or edit="8"> (delete for everyone)
    function isDeleteMessage(node) {
        if (!node || node.tag !== 'message') return false;
        return node.attrs.edit === '7' || node.attrs.edit === '8';
    }

    // 6. Delivery receipts: <receipt to="..." id="..."> (no type attr = delivery receipt)
    //    Also: <ack class="receipt" ...> without type
    function isDeliveryReceipt(node) {
        if (!node) return false;
        // Outgoing delivery receipt (telling sender you received their message)
        if (node.tag === 'receipt' && !node.attrs.type && node.attrs.to) return true;
        return false;
    }

    // 7. Recording indicator: <chatstate to="..."><composing media="audio" /></chatstate>
    function isRecordingIndicator(node) {
        if (!node || node.tag !== 'chatstate') return false;
        if (!Array.isArray(node.content)) return false;
        return node.content.some(c => c.tag === 'composing' && c.attrs && c.attrs.media === 'audio');
    }

    // =============================================
    // Frame Modifiers
    // =============================================

    function stripType(node) {
        const newAttrs = {};
        for (const [k, v] of Object.entries(node.attrs)) {
            if (k !== 'type') newAttrs[k] = v;
        }
        return { tag: node.tag, attrs: newAttrs, content: node.content };
    }

    // =============================================
    // Traffic Logger
    // =============================================
    function logFrame(dir, data, label) {
        const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
        const node = decodeFrame(bytes);
        const entry = { dir, time: new Date().toISOString(), size: bytes.length, node, label };
        traffic.push(entry);

        const arrow = dir === 'IN' ? '📥' : '📤';
        const color = dir === 'IN' ? 'color: #4f4' : 'color: #4af';
        const mod = label ? ` ${label}` : '';

        if (node) {
            console.log(`%c${arrow} ${dir}${mod} [${bytes.length}B] ${prettyNode(node)}`, color);
        }
    }

    // =============================================
    // Encrypt Hook — Outgoing Frame Manipulation
    // =============================================
    function processOutgoing(algo, key, data) {
        const pt = new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer || data);
        if (pt.length <= 3) return null;

        const node = decodeFrame(pt);
        if (!node) return null;

        // --- Recording indicator (check BEFORE typing since it's a subtype) ---
        if (flags.blockRecording && isRecordingIndicator(node)) {
            blockedLog.push({ time: new Date().toISOString(), type: '🎙️ recording', to: node.attrs.to });
            console.log(`%c🎙️ BLOCKED recording indicator → ${node.attrs.to}`, 'color: #fa0; font-weight: bold');
            return 'DROP'; // don't send anything
        }

        // --- Typing indicator ---
        if (flags.blockTyping && isTypingIndicator(node) && !isRecordingIndicator(node)) {
            blockedLog.push({ time: new Date().toISOString(), type: '⌨️ typing', to: node.attrs.to });
            console.log(`%c⌨️ BLOCKED typing indicator → ${node.attrs.to}`, 'color: #fa0; font-weight: bold');
            return 'DROP';
        }

        // --- Ghost mode (online presence) ---
        if (flags.ghostMode && isPresenceAvailable(node)) {
            blockedLog.push({ time: new Date().toISOString(), type: '👻 presence', detail: node.attrs.type });
            console.log(`%c👻 BLOCKED presence ${node.attrs.type}`, 'color: #888; font-weight: bold');
            return 'DROP';
        }

        // --- Read receipts ---
        if (flags.blockReads && isReadReceipt(node)) {
            const modified = stripType(node);
            const newBytes = encodeFrame(modified);
            blockedLog.push({ time: new Date().toISOString(), type: '📖 read', to: node.attrs.to, id: node.attrs.id });
            console.log(`%c📖 BLOCKED read receipt → ${node.attrs.to} (id: ${node.attrs.id})`, 'color: #f44; font-weight: bold');
            logFrame('OUT', newBytes, '⛔');
            return newBytes;
        }

        // --- Played receipts ---
        if (flags.blockPlayed && isPlayedReceipt(node)) {
            const modified = stripType(node);
            const newBytes = encodeFrame(modified);
            blockedLog.push({ time: new Date().toISOString(), type: '🎵 played', to: node.attrs.to, id: node.attrs.id });
            console.log(`%c🎵 BLOCKED played receipt → ${node.attrs.to} (id: ${node.attrs.id})`, 'color: #a4f; font-weight: bold');
            logFrame('OUT', newBytes, '⛔');
            return newBytes;
        }

        // --- Delivery receipts ---
        if (flags.blockDelivery && isDeliveryReceipt(node)) {
            blockedLog.push({ time: new Date().toISOString(), type: '✓✓ delivery', to: node.attrs.to, id: node.attrs.id });
            console.log(`%c✓✓ BLOCKED delivery receipt → ${node.attrs.to} (id: ${node.attrs.id})`, 'color: #888; font-weight: bold');
            return 'DROP';
        }

        logFrame('OUT', pt);
        return null; // no modification
    }

    // =============================================
    // Decrypt Hook — Incoming Frame Detection
    // =============================================
    function processIncoming(pt) {
        if (pt.length <= 3) return;
        const node = decodeFrame(pt);
        if (!node) return;

        // Anti-delete: detect incoming message deletions
        if (isDeleteMessage(node)) {
            const entry = {
                time: new Date().toISOString(),
                from: node.attrs.from || node.attrs.participant,
                id: node.attrs.id,
                editType: node.attrs.edit, // "7" = own delete, "8" = admin delete
                node: prettyNode(node)
            };
            deletedLog.push(entry);
            const who = node.attrs.participant || node.attrs.from || '?';
            const kind = node.attrs.edit === '8' ? 'ADMIN ' : '';
            console.log(`%c🗑️ MESSAGE ${kind}DELETED by ${who} (id: ${node.attrs.id})`,
                'color: #ff4444; font-weight: bold; font-size: 14px; background: #330000; padding: 2px 6px; border-radius: 4px');
        }

        logFrame('IN', pt);
    }

    // =============================================
    // Hook crypto.subtle
    // =============================================
    if (!window.__realCryptoDecrypt) {
        window.__realCryptoDecrypt = crypto.subtle.decrypt.bind(crypto.subtle);
        window.__realCryptoEncrypt = crypto.subtle.encrypt.bind(crypto.subtle);
    }

    crypto.subtle.decrypt = async function(algo, key, data) {
        const result = await window.__realCryptoDecrypt(algo, key, data);
        if (algo?.name === 'AES-GCM') {
            processIncoming(new Uint8Array(result));
        }
        return result;
    };

    crypto.subtle.encrypt = async function(algo, key, data) {
        if (algo?.name === 'AES-GCM') {
            const action = processOutgoing(algo, key, data);
            if (action === 'DROP') {
                // Return a valid but empty ciphertext — WA will see an error and skip
                // Actually, we need to encrypt SOMETHING valid. Send a minimal no-op.
                // Best approach: just encrypt the original but don't call the real encrypt
                // Returning empty would cause errors. Instead, just proceed but the frame won't matter.
                // Actually the cleanest way: encrypt a minimal valid frame
                const noop = encodeFrame({ tag: 'ib', attrs: {}, content: undefined });
                return window.__realCryptoEncrypt(algo, key, noop.buffer);
            }
            if (action instanceof Uint8Array) {
                return window.__realCryptoEncrypt(algo, key, action.buffer);
            }
        }
        return window.__realCryptoEncrypt(algo, key, data);
    };

    // =============================================
    // User Commands
    // =============================================

    // Read receipts
    window.blockReads = () => { flags.blockReads = true; console.log('%c📖 Read receipt blocking ON — no blue ticks sent', 'color: #f44; font-size: 14px'); };
    window.allowReads = () => { flags.blockReads = false; console.log('%c✅ Read receipt blocking OFF', 'color: #0f0; font-size: 14px'); };

    // Played receipts
    window.blockPlayed = () => { flags.blockPlayed = true; console.log('%c🎵 Played receipt blocking ON — voice note "played" hidden', 'color: #a4f; font-size: 14px'); };
    window.allowPlayed = () => { flags.blockPlayed = false; console.log('%c✅ Played receipt blocking OFF', 'color: #0f0; font-size: 14px'); };

    // Typing indicators
    window.blockTyping = () => { flags.blockTyping = true; console.log('%c⌨️ Typing indicator blocking ON — "typing..." hidden', 'color: #fa0; font-size: 14px'); };
    window.allowTyping = () => { flags.blockTyping = false; console.log('%c✅ Typing indicator blocking OFF', 'color: #0f0; font-size: 14px'); };

    // Ghost mode (presence)
    window.goGhost = () => { flags.ghostMode = true; console.log('%c👻 Ghost mode ON — you appear offline', 'color: #888; font-size: 14px'); };
    window.goVisible = () => { flags.ghostMode = false; console.log('%c✅ Ghost mode OFF — presence visible', 'color: #0f0; font-size: 14px'); };

    // Delivery receipts
    window.blockDelivery = () => { flags.blockDelivery = true; console.log('%c✓✓ Delivery receipt blocking ON — grey ticks hidden', 'color: #888; font-size: 14px'); };
    window.allowDelivery = () => { flags.blockDelivery = false; console.log('%c✅ Delivery receipt blocking OFF', 'color: #0f0; font-size: 14px'); };

    // Recording indicator
    window.blockRecording = () => { flags.blockRecording = true; console.log('%c🎙️ Recording indicator blocking ON', 'color: #fa0; font-size: 14px'); };
    window.allowRecording = () => { flags.blockRecording = false; console.log('%c✅ Recording indicator blocking OFF', 'color: #0f0; font-size: 14px'); };

    // Status overview
    window.status = () => {
        console.log('%c📊 Current Settings:', 'font-weight: bold; font-size: 14px');
        const items = [
            ['📖 Read receipts',     flags.blockReads,     'No blue ticks sent'],
            ['🎵 Played receipts',   flags.blockPlayed,    'Voice note "played" hidden'],
            ['⌨️ Typing indicator',  flags.blockTyping,    '"typing..." hidden from others'],
            ['👻 Ghost mode',        flags.ghostMode,      'Appear offline while browsing'],
            ['✓✓ Delivery receipts', flags.blockDelivery,  'Grey double-checks hidden'],
            ['🎙️ Recording indicator', flags.blockRecording, '"recording..." hidden'],
        ];
        for (const [name, on, desc] of items) {
            const st = on ? '🔴 BLOCKED' : '🟢 normal';
            console.log(`  ${name}: ${st} — ${desc}`);
        }
        console.log(`\n  📊 ${blockedLog.length} items blocked, ${deletedLog.length} deletions detected`);
    };

    // Show blocked items
    window.showBlocked = () => {
        console.log(`%c⛔ ${blockedLog.length} items blocked:`, 'font-weight: bold');
        const last20 = blockedLog.slice(-20);
        last20.forEach((b, i) => {
            const target = b.to || b.detail || '';
            const id = b.id ? ` (${b.id})` : '';
            console.log(`  [${blockedLog.length - last20.length + i}] ${b.type} ${b.time} → ${target}${id}`);
        });
        if (blockedLog.length > 20) console.log(`  ... and ${blockedLog.length - 20} more`);
    };

    // Show detected deletions
    window.showDeleted = () => {
        console.log(`%c🗑️ ${deletedLog.length} message deletions detected:`, 'font-weight: bold; color: #f44');
        deletedLog.forEach((d, i) => {
            const kind = d.editType === '8' ? ' [ADMIN]' : '';
            console.log(`  [${i}] ${d.time} — from: ${d.from}${kind} (msg id: ${d.id})`);
        });
    };

    // Traffic viewer
    window.showTraffic = (n) => {
        n = n || 20;
        const recent = traffic.slice(-n);
        console.log(`%c📋 Last ${recent.length} of ${traffic.length} frames:`, 'font-weight: bold');
        recent.forEach((e, i) => {
            const arrow = e.dir === 'IN' ? '📥' : '📤';
            const color = e.dir === 'IN' ? 'color: #4f4' : 'color: #4af';
            const mod = e.label ? ` ${e.label}` : '';
            if (e.node) console.log(`%c[${i}] ${arrow}${mod} ${prettyNode(e.node)}`, color);
        });
    };

    window.filterTraffic = (kw) => {
        const matches = traffic.filter(e => e.node && prettyNode(e.node).toLowerCase().includes(kw.toLowerCase()));
        console.log(`%c🔎 ${matches.length} frames matching "${kw}":`, 'font-weight: bold');
        matches.slice(-30).forEach((e, i) => {
            const color = e.dir === 'IN' ? 'color: #4f4' : 'color: #4af';
            console.log(`%c[${i}] ${e.dir==='IN'?'📥':'📤'} ${prettyNode(e.node)}`, color);
        });
    };

    // =============================================
    // Startup Banner
    // =============================================
    console.log('%c🔒 Traffic Manipulator v3 ACTIVE', 'color: #f44; font-size: 16px; font-weight: bold');
    console.log('%cFeature Controls:', 'font-weight: bold');
    console.log('  📖 blockReads() / allowReads()       — blue ticks (default: BLOCKED)');
    console.log('  🎵 blockPlayed() / allowPlayed()     — voice note played status');
    console.log('  ⌨️  blockTyping() / allowTyping()     — typing indicator');
    console.log('%cMonitoring:', 'font-weight: bold');
    console.log('  showTraffic(N) — show last N frames');
    console.log('  filterTraffic("keyword") — search frames');
    console.log('  status()       — show current feature status');
})();
