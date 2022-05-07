#!/usr/bin/env bash

echoContent() {
	case $1 in
	# 红色
	"red")
		# shellcheck disable=SC2154
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		# 天蓝色
	"skyBlue")
		${echoType} "\033[1;36m${printN}$2 \033[0m"
		;;
		# 绿色
	"green")
		${echoType} "\033[32m${printN}$2 \033[0m"
		;;
		# 白色
	"white")
		${echoType} "\033[37m${printN}$2 \033[0m"
		;;
	"magenta")
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		# 黄色
	"yellow")
		${echoType} "\033[33m${printN}$2 \033[0m"
		;;
	esac
}
configPath=/etc/v2ray-agent/xray/conf/

echoContent skyBlue "===================== 删除已到期账号 ======================\n"
jq .inbounds[0].settings.clients ${configPath}02_VLESS_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
echoContent skyBlue "\n ---> 帐号: $(echo "${user}" | jq -r .email)"
echoContent skyBlue " ---> expird date: $(echo "${user}" | jq -r .expird)"
echo
defaultBase64Code vlesstcp "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)"
done

echo "done"