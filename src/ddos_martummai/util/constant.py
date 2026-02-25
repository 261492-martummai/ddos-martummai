IP_COLUMN_NAME = "src_ip"

COLUMN_RENAME_MAP = {
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_min": "Fwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "fwd_header_len": "Fwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "syn_flag_cnt": "SYN Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "cwr_flag_count": "CWE Flag Count",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
    "active_mean": "Active Mean",
    "idle_mean": "Idle Mean",
}

CONTEXT_SETTINGS = dict(
    help_option_names=["--help"],
    max_content_width=120,
)
