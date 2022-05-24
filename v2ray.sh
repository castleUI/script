#!/usr/bin/env bash
clear

#black='\e[1;30m'
#red='\e[1;31m'
#green='\e[1;32m'
#yellow='\e[1;33m'
#blue='\e[1;34m'
#purple='\e[0;35m'
#nc='\e[0m'

echoContent() {
	case $1 in
	# 红色
	"red")
		# shellcheck disable=SC2154
		${echoType} "\033[1;31m${printN}$2 \033[0m"
		;;
		# 天蓝色
	"skyBlue")
		${echoType} "\033[1;36m${printN}$2 \033[0m"
		;;
		# 绿色
	"green")
		${echoType} "\033[1;32m${printN}$2 \033[0m"
		;;
		# 白色
	"white")
		${echoType} "\033[37m${printN}$2 \033[0m"
		;;
	"magenta")
		${echoType} "\033[0;35m${printN}$2 \033[0m"
		;;
		# 黄色
	"yellow")
		${echoType} "\033[1;33m${printN}$2 \033[0m"
		;;
	esac
}

# 初始化全局变量
initVar() {
	installType='yum -y install'
	removeType='yum -y remove'
	upgrade="yum -y update"
	echoType='echo -e'

	# 核心支持的cpu版本
	xrayCoreCPUVendor=""
	v2rayCoreCPUVendor=""
	# hysteriaCoreCPUVendor=""

	# 域名
	domain=

	# CDN节点的address
	add=

	# 安装总进度
	totalProgress=1

	# 1.xray-core安装
	# 2.v2ray-core 安装
	# 3.v2ray-core[xtls] 安装
	coreInstallType=

	# 核心安装path
	# coreInstallPath=

	# v2ctl Path
	ctlPath=
	# 1.全部安装
	# 2.个性化安装
	# v2rayAgentInstallType=

	# 当前的个性化安装方式 01234
	currentInstallProtocolType=

	# 当前alpn的顺序
	currentAlpn=

	# 前置类型
	frontingType=

	# 选择的个性化安装方式
	selectCustomInstallType=

	# v2ray-core、xray-core配置文件的路径
	configPath=

	# 配置文件的path
	currentPath=

	# 配置文件的host
	currentHost=

	# 安装时选择的core类型
	selectCoreType=

	# 默认core版本
	v2rayCoreVersion=

	# 随机路径
	customPath=

	# centos version
	centosVersion=

	# UUID
	currentUUID=

	# previousClients
	previousClients=

	localIP=

	# 集成更新证书逻辑不再使用单独的脚本--RenewTLS
	renewTLS=$1

	# tls安装失败后尝试的次数
	installTLSCount=

	# BTPanel状态
	BTPanelStatus=

	# nginx配置文件路径
	nginxConfigPath=/etc/nginx/conf.d/
}

# 检测安装方式
readInstallType() {
	coreInstallType=
	configPath=

	# 1.检测安装目录
	if [[ -d "/etc/v2ray-agent" ]]; then
		# 检测安装方式 v2ray-core
		if [[ -d "/etc/v2ray-agent/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ctl" ]]; then
			if [[ -d "/etc/v2ray-agent/v2ray/conf" && -f "/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json" ]]; then
				configPath=/etc/v2ray-agent/v2ray/conf/

				if grep </etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json -q '"security": "tls"'; then
					# 不带XTLS的v2ray-core
					coreInstallType=2
					ctlPath=/etc/v2ray-agent/v2ray/v2ctl
				elif grep </etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json -q '"security": "xtls"'; then
					# 带XTLS的v2ray-core
					ctlPath=/etc/v2ray-agent/v2ray/v2ctl
					coreInstallType=3
				fi
			fi
		fi

		if [[ -d "/etc/v2ray-agent/xray" && -f "/etc/v2ray-agent/xray/xray" ]]; then
			# 这里检测xray-core
			if [[ -d "/etc/v2ray-agent/xray/conf" ]] && [[ -f "/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json" || -f "/etc/v2ray-agent/xray/conf/02_trojan_TCP_inbounds.json" ]]; then
				# xray-core
				configPath=/etc/v2ray-agent/xray/conf/
				ctlPath=/etc/v2ray-agent/xray/xray
				coreInstallType=1
			fi
		fi
	fi
}

# 重启核心
reloadCore() {
	if [[ "${coreInstallType}" == "1" ]]; then
		handleXray stop
		handleXray start
	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
		handleV2Ray stop
		handleV2Ray start
	fi
}

# 操作V2Ray
handleV2Ray() {
	# shellcheck disable=SC2010
	if find /bin /usr/bin | grep -q systemctl && ls /etc/systemd/system/ | grep -q v2ray.service; then
		if [[ -z $(pgrep -f "v2ray/v2ray") ]] && [[ "$1" == "start" ]]; then
			systemctl start v2ray.service
		elif [[ -n $(pgrep -f "v2ray/v2ray") ]] && [[ "$1" == "stop" ]]; then
			systemctl stop v2ray.service
		fi
	fi
	sleep 0.8

	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "v2ray/v2ray") ]]; then
			echoContent green " ---> V2Ray启动成功"
		else
			echoContent red "V2Ray启动失败"
			echoContent red "请手动执行【/etc/v2ray-agent/v2ray/v2ray -confdir /etc/v2ray-agent/v2ray/conf】，查看错误日志"
			exit 0
		fi
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "v2ray/v2ray") ]]; then
			echoContent green " ---> V2Ray关闭成功"
		else
			echoContent red "V2Ray关闭失败"
			echoContent red "请手动执行【ps -ef|grep -v grep|grep v2ray|awk '{print \$2}'|xargs kill -9】"
			exit 0
		fi
	fi
}
# 操作xray
handleXray() {
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]] && [[ -n $(find /etc/systemd/system/ -name "xray.service") ]]; then
		if [[ -z $(pgrep -f "xray/xray") ]] && [[ "$1" == "start" ]]; then
			systemctl start xray.service
		elif [[ -n $(pgrep -f "xray/xray") ]] && [[ "$1" == "stop" ]]; then
			systemctl stop xray.service
		fi
	fi

	sleep 0.8

	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "xray/xray") ]]; then
			echoContent green " ---> Xray启动成功"
		else
			echoContent red "Xray启动失败"
			echoContent red "请手动执行【/etc/v2ray-agent/xray/xray -confdir /etc/v2ray-agent/xray/conf】，查看错误日志"
			exit 0
		fi
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "xray/xray") ]]; then
			echoContent green " ---> Xray关闭成功"
		else
			echoContent red "xray关闭失败"
			echoContent red "请手动执行【ps -ef|grep -v grep|grep xray|awk '{print \$2}'|xargs kill -9】"
			exit 0
		fi
	fi
}

# 自定义uuid
customUUID() {
	#	read -r -p "是否自定义UUID ？[y/n]:" customUUIDStatus
	#	echo
	#	if [[ "${customUUIDStatus}" == "y" ]]; then
	read -r -p "请输入合法的UUID，[回车]随机UUID:" currentCustomUUID
	echo
	if [[ -z "${currentCustomUUID}" ]]; then
		# echoContent red " ---> UUID不可为空"
		currentCustomUUID=$(${ctlPath} uuid)
		echoContent yellow "uuid:${currentCustomUUID}\n"

	else
		jq -r -c '.inbounds[0].settings.clients[].id' ${configPath}${frontingType}.json | while read -r line; do
			if [[ "${line}" == "${currentCustomUUID}" ]]; then
				echo >/tmp/v2ray-agent
			fi
		done
		if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
			echoContent red " ---> UUID不可重复"
			rm /tmp/v2ray-agent
			exit 0
		fi
	fi
	#	fi
}
# 自定义email
customUserEmail() {
	#	read -r -p "是否自定义email ？[y/n]:" customEmailStatus
	#	echo
	#	if [[ "${customEmailStatus}" == "y" ]]; then
	read -r -p "请输入合法的email，[回车]随机email:" currentCustomEmail
	echo
	if [[ -z "${currentCustomEmail}" ]]; then
		currentCustomEmail="${currentHost}_${currentCustomUUID}"
		echoContent yellow "email: ${currentCustomEmail}\n"
		#		echoContent red " ---> email不可为空"
	else
		jq -r -c '.inbounds[0].settings.clients[].email' ${configPath}${frontingType}.json | while read -r line; do
			if [[ "${line}" == "${currentCustomEmail}" ]]; then
				echo >/tmp/v2ray-agent
			fi
		done
		if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
			echoContent red " ---> email不可重复"
			rm /tmp/v2ray-agent
			exit 0
		fi
	fi
	#	fi
}

# 检测安装方式
readInstallType() {
	coreInstallType=
	configPath=

	# 1.检测安装目录
	if [[ -d "/etc/v2ray-agent" ]]; then
		# 检测安装方式 v2ray-core
		if [[ -d "/etc/v2ray-agent/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ctl" ]]; then
			if [[ -d "/etc/v2ray-agent/v2ray/conf" && -f "/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json" ]]; then
				configPath=/etc/v2ray-agent/v2ray/conf/

				if grep </etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json -q '"security": "tls"'; then
					# 不带XTLS的v2ray-core
					coreInstallType=2
					ctlPath=/etc/v2ray-agent/v2ray/v2ctl
				elif grep </etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json -q '"security": "xtls"'; then
					# 带XTLS的v2ray-core
					ctlPath=/etc/v2ray-agent/v2ray/v2ctl
					coreInstallType=3
				fi
			fi
		fi

		if [[ -d "/etc/v2ray-agent/xray" && -f "/etc/v2ray-agent/xray/xray" ]]; then
			# 这里检测xray-core
			if [[ -d "/etc/v2ray-agent/xray/conf" ]] && [[ -f "/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json" || -f "/etc/v2ray-agent/xray/conf/02_trojan_TCP_inbounds.json" ]]; then
				# xray-core
				configPath=/etc/v2ray-agent/xray/conf/
				ctlPath=/etc/v2ray-agent/xray/xray
				coreInstallType=1
			fi
		fi
	fi
}
# 读取协议类型
readInstallProtocolType() {
	currentInstallProtocolType=

	while read -r row; do
		if echo "${row}" | grep -q 02_trojan_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'trojan'
			frontingType=02_trojan_TCP_inbounds
		fi
		if echo "${row}" | grep -q VLESS_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'0'
			frontingType=02_VLESS_TCP_inbounds
		fi
		if echo "${row}" | grep -q VLESS_WS_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'1'
		fi
		if echo "${row}" | grep -q trojan_gRPC_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'2'
		fi
		if echo "${row}" | grep -q VMess_WS_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'3'
		fi
		if echo "${row}" | grep -q 04_trojan_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'4'
		fi
		if echo "${row}" | grep -q VLESS_gRPC_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'5'
		fi
	done < <(find ${configPath} -name "*inbounds.json" | awk -F "[.]" '{print $1}')
}

# 检查文件目录以及path路径
readConfigHostPathUUID() {
	currentPath=
	currentDefaultPort=
	currentUUID=
	currentHost=
	#	currentPort=
	currentAdd=
	# 读取path
	if [[ -n "${configPath}" ]]; then
		local fallback
		fallback=$(jq -r -c '.inbounds[0].settings.fallbacks[]|select(.path)' ${configPath}${frontingType}.json | head -1)

		local path
		path=$(echo "${fallback}" | jq -r .path | awk -F "[/]" '{print $2}')

		if [[ $(echo "${fallback}" | jq -r .dest) == 31297 ]]; then
			currentPath=$(echo "${path}" | awk -F "[w][s]" '{print $1}')
		elif [[ $(echo "${fallback}" | jq -r .dest) == 31298 ]]; then
			currentPath=$(echo "${path}" | awk -F "[t][c][p]" '{print $1}')
		elif [[ $(echo "${fallback}" | jq -r .dest) == 31299 ]]; then
			currentPath=$(echo "${path}" | awk -F "[v][w][s]" '{print $1}')
		fi
		# 尝试读取alpn h2 Path

		if [[ -z "${currentPath}" ]]; then
			dest=$(jq -r -c '.inbounds[0].settings.fallbacks[]|select(.alpn)|.dest' ${configPath}${frontingType}.json | head -1)
			if [[ "${dest}" == "31302" || "${dest}" == "31304" ]]; then

				if grep -q "trojangrpc {" <${nginxConfigPath}alone.conf; then
					currentPath=$(grep "trojangrpc {" <${nginxConfigPath}alone.conf | awk -F "[/]" '{print $2}' | awk -F "[t][r][o][j][a][n]" '{print $1}')
				elif grep -q "grpc {" <${nginxConfigPath}alone.conf; then
					currentPath=$(grep "grpc {" <${nginxConfigPath}alone.conf | head -1 | awk -F "[/]" '{print $2}' | awk -F "[g][r][p][c]" '{print $1}')
				fi
			fi
		fi


		local defaultPortFile=
		defaultPortFile=$(find ${configPath}* | grep "default")

		if [[ -n "${defaultPortFile}" ]]; then
			currentDefaultPort=$(echo "${defaultPortFile}" | awk -F [_] '{print $4}')
		else
			currentDefaultPort=443
		fi

	fi
	if [[ "${coreInstallType}" == "1" ]]; then
		currentHost=$(jq -r .inbounds[0].streamSettings.xtlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
		currentAdd=$(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json)
		if [[ "${currentAdd}" == "null" ]]; then
			currentAdd=${currentHost}
		fi
		#		currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)

	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
		if [[ "${coreInstallType}" == "3" ]]; then

			currentHost=$(jq -r .inbounds[0].streamSettings.xtlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		else
			currentHost=$(jq -r .inbounds[0].streamSettings.tlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		fi
		currentAdd=$(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json)

		if [[ "${currentAdd}" == "null" ]]; then
			currentAdd=${currentHost}
		fi
		currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
		#		currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)
	fi
}

# 通用
defaultBase64Code() {
	local type=$1
	local email=$2
	local id=$3

	port=${currentDefaultPort}

	local subAccount
	subAccount=$(echo "${email}" | awk -F "[_]" '{print $1}')_$(echo "${id}_currentHost" | md5sum | awk '{print $1}')
	if [[ "${type}" == "vlesstcp" ]]; then

		if [[ "${coreInstallType}" == "1" ]] && echo "${currentInstallProtocolType}" | grep -q 0; then
			echoContent yellow " ---> 通用格式(VLESS+TCP+TLS/xtls-rprx-direct)"
			echoContent green "    vless://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=YourBug&headerType=none&sni=YourBug&flow=xtls-rprx-direct#${email}\n"

			#echoContent yellow " ---> 格式化明文(VLESS+TCP+TLS/xtls-rprx-direct)"
			#echoContent green "协议类型:VLESS，地址:${currentHost}，端口:${currentDefaultPort}，用户ID:${id}，安全:xtls，传输方式:tcp，flow:xtls-rprx-direct，账户名:${email}\n"
			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-direct#${email}
EOF
			#echoContent yellow " ---> 二维码 VLESS(VLESS+TCP+TLS/xtls-rprx-direct)"
			#echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${currentHost}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${currentHost}%3D${currentHost}%26headerType%3Dnone%26sni%3D${currentHost}%26flow%3Dxtls-rprx-direct%23${email}\n"

			#echoContent skyBlue "----------------------------------------------------------------------------------"

			#echoContent yellow " ---> 通用格式(VLESS+TCP+TLS/xtls-rprx-splice)"
			#echoContent green "    vless://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=YourBug&headerType=none&sni=YourBug&flow=xtls-rprx-splice#${email/direct/splice}\n"

			#echoContent yellow " ---> 格式化明文(VLESS+TCP+TLS/xtls-rprx-splice)"
			#echoContent green "    协议类型:VLESS，地址:${currentHost}，端口:${currentDefaultPort}，用户ID:${id}，安全:xtls，传输方式:tcp，flow:xtls-rprx-splice，账户名:${email/direct/splice}\n"
			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-splice#${email/direct/splice}
EOF
			#echoContent yellow " ---> 二维码 VLESS(VLESS+TCP+TLS/xtls-rprx-splice)"
			#echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${currentHost}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${currentHost}%3D${currentHost}%26headerType%3Dnone%26sni%3D${currentHost}%26flow%3Dxtls-rprx-splice%23${email/direct/splice}\n"

		elif [[ "${coreInstallType}" == 2 || "${coreInstallType}" == "3" ]]; then
			echoContent yellow " ---> 通用格式(VLESS+TCP+TLS)"
			echoContent green "    vless://${id}@${currentHost}:${currentDefaultPort}?security=tls&encryption=none&host=${currentHost}&headerType=none&type=tcp#${email}\n"

			#echoContent yellow " ---> 格式化明文(VLESS+TCP+TLS/xtls-rprx-splice)"
			#echoContent green "    协议类型:VLESS，地址:${currentHost}，端口:${currentDefaultPort}，用户ID:${id}，安全:tls，传输方式:tcp，账户名:${email/direct/splice}\n"

			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${currentHost}:${currentDefaultPort}?security=tls&encryption=none&host=${currentHost}&headerType=none&type=tcp#${email}
EOF
			#echoContent yellow " ---> 二维码 VLESS(VLESS+TCP+TLS)"
			#echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3a%2f%2f${id}%40${currentHost}%3a${currentDefaultPort}%3fsecurity%3dtls%26encryption%3dnone%26host%3d${currentHost}%26headerType%3dnone%26type%3dtcp%23${email}\n"
		fi

	elif [[ "${type}" == "trojanTCPXTLS" ]]; then
		echoContent yellow " ---> 通用格式(Trojan+TCP+TLS/xtls-rprx-direct)"
		echoContent green "    trojan://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-direct#${email}\n"

		#echoContent yellow " ---> 格式化明文(Trojan+TCP+TLS/xtls-rprx-direct)"
		#echoContent green "协议类型:Trojan，地址:${currentHost}，端口:${currentDefaultPort}，用户ID:${id}，安全:xtls，传输方式:tcp，flow:xtls-rprx-direct，账户名:${email}\n"
		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-direct#${email}
EOF
		#echoContent yellow " ---> 二维码 Trojan(Trojan+TCP+TLS/xtls-rprx-direct)"
		#echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3A%2F%2F${id}%40${currentHost}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${currentHost}%3D${currentHost}%26headerType%3Dnone%26sni%3D${currentHost}%26flow%3Dxtls-rprx-direct%23${email}\n"

		#echoContent skyBlue "----------------------------------------------------------------------------------"

		echoContent yellow " ---> 通用格式(Trojan+TCP+TLS/xtls-rprx-splice)"
		echoContent green "    trojan://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-splice#${email/direct/splice}\n"

		#echoContent yellow " ---> 格式化明文(Trojan+TCP+TLS/xtls-rprx-splice)"
		#echoContent green "    协议类型:VLESS，地址:${currentHost}，端口:${currentDefaultPort}，用户ID:${id}，安全:xtls，传输方式:tcp，flow:xtls-rprx-splice，账户名:${email/direct/splice}\n"
		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-splice#${email/direct/splice}
EOF
		#echoContent yellow " ---> 二维码 Trojan(Trojan+TCP+TLS/xtls-rprx-splice)"
		#echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3A%2F%2F${id}%40${currentHost}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${currentHost}%3D${currentHost}%26headerType%3Dnone%26sni%3D${currentHost}%26flow%3Dxtls-rprx-splice%23${email/direct/splice}\n"

	elif [[ "${type}" == "vmessws" ]]; then
		qrCodeBase64Default=$(echo -n "{\"port\":${currentDefaultPort},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\"none\",\"path\":\"/${currentPath}vws\",\"net\":\"ws\",\"add\":\"${currentAdd}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}" | base64 -w 0)
		qrCodeBase64Default="${qrCodeBase64Default// /}"

		#echoContent yellow " ---> 通用json(VMess+WS+TLS)"
		#echoContent green "    {\"port\":${currentDefaultPort},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\"none\",\"path\":\"/${currentPath}vws\",\"net\":\"ws\",\"add\":\"${currentAdd}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}\n"
		#echoContent yellow " ---> 通用vmess(VMess+WS+TLS)链接"
		#echoContent green "    vmess://${qrCodeBase64Default}\n"
		#echoContent yellow " ---> 二维码 vmess(VMess+WS+TLS)"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vmess://${qrCodeBase64Default}
EOF
		#echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

		#	elif [[ "${type}" == "vmesstcp" ]]; then
		#
		#		echoContent red "path:${path}"
		#		qrCodeBase64Default=$(echo -n "{\"add\":\"${add}\",\"aid\":0,\"host\":\"${host}\",\"id\":\"${id}\",\"net\":\"tcp\",\"path\":\"${path}\",\"port\":${port},\"ps\":\"${email}\",\"scy\":\"none\",\"sni\":\"${host}\",\"tls\":\"tls\",\"v\":2,\"type\":\"http\",\"allowInsecure\":0,\"peer\":\"${host}\",\"obfs\":\"http\",\"obfsParam\":\"${host}\"}" | base64)
		#		qrCodeBase64Default="${qrCodeBase64Default// /}"
		
		#		echoContent yellow " ---> 通用json(VMess+TCP+TLS)"
		#		echoContent green "    {\"port\":'${port}',\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${host}\",\"type\":\"http\",\"path\":\"${path}\",\"net\":\"http\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"post\",\"peer\":\"${host}\",\"obfs\":\"http\",\"obfsParam\":\"${host}\"}\n"
				echoContent yellow " ---> 通用vmess(VMess+TCP+TLS)链接"
				echoContent green "    vmess://${qrCodeBase64Default}\n"
		
		#		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
		#vmess://${qrCodeBase64Default}
		#EOF
		#		echoContent yellow " ---> 二维码 vmess(VMess+TCP+TLS)"
		#		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

	elif [[ "${type}" == "vlessws" ]]; then

		echoContent yellow " ---> 通用格式(VLESS+WS+TLS)"
		echoContent green "    vless://${id}@${currentAdd}:${currentDefaultPort}?encryption=none&security=tls&type=ws&host=${currentHost}&sni=${currentHost}&path=/${currentPath}ws#${email}\n"

		#echoContent yellow " ---> 格式化明文(VLESS+WS+TLS)"
		#echoContent green "    协议类型:VLESS，地址:${currentAdd}，伪装域名/SNI:${currentHost}，端口:${currentDefaultPort}，用户ID:${id}，安全:tls，传输方式:ws，路径:/${currentPath}ws，账户名:${email}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${currentAdd}:${currentDefaultPort}?encryption=none&security=tls&type=ws&host=${currentHost}&sni=${currentHost}&path=/${currentPath}ws#${email}
EOF

		#echoContent yellow " ---> 二维码 VLESS(VLESS+WS+TLS)"
		#echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${currentAdd}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dws%26host%3D${currentHost}%26sni%3D${currentHost}%26path%3D%252f${currentPath}ws%23${email}"

	elif [[ "${type}" == "vlessgrpc" ]]; then

		echoContent yellow " ---> 通用格式(VLESS+gRPC+TLS)"
		echoContent green "    vless://${id}@${currentAdd}:${currentDefaultPort}?encryption=none&security=tls&type=grpc&host=${currentHost}&path=${currentPath}grpc&serviceName=${currentPath}grpc&alpn=h2&sni=${currentHost}#${email}\n"

		#echoContent yellow " ---> 格式化明文(VLESS+gRPC+TLS)"
		#echoContent green "    协议类型:VLESS，地址:${currentAdd}，伪装域名/SNI:${currentHost}，端口:${currentDefaultPort}，用户ID:${id}，安全:tls，传输方式:gRPC，alpn:h2，serviceName:${currentPath}grpc，账户名:${email}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${currentAdd}:${currentDefaultPort}?encryption=none&security=tls&type=grpc&host=${currentHost}&path=${currentPath}grpc&serviceName=${currentPath}grpc&alpn=h2&sni=${currentHost}#${email}
EOF
		#echoContent yellow " ---> 二维码 VLESS(VLESS+gRPC+TLS)"
		#echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${currentAdd}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dgrpc%26host%3D${currentHost}%26serviceName%3D${currentPath}grpc%26path%3D${currentPath}grpc%26sni%3D${currentHost}%26alpn%3Dh2%23${email}"

	elif [[ "${type}" == "trojan" ]]; then
		# URLEncode
		echoContent yellow " ---> Trojan(TLS)"
		echoContent green "    trojan://${id}@${currentHost}:${currentDefaultPort}?peer=${currentHost}&sni=${currentHost}&alpn=http/1.1#${currentHost}_Trojan\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${currentHost}:${currentDefaultPort}?peer=${currentHost}&sni=${currentHost}&alpn=http/1.1#${email}_Trojan
EOF
		#echoContent yellow " ---> 二维码 Trojan(TLS)"
		#echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${currentHost}%3a${port}%3fpeer%3d${currentHost}%26sni%3d${currentHost}%26alpn%3Dhttp/1.1%23${email}\n"

	elif [[ "${type}" == "trojangrpc" ]]; then
		# URLEncode

		echoContent yellow " ---> Trojan gRPC(TLS)"
		echoContent green "    trojan://${id}@${currentAdd}:${currentDefaultPort}?encryption=none&peer=${currentHost}&security=tls&type=grpc&sni=${currentHost}&alpn=h2&path=${currentPath}trojangrpc&serviceName=${currentPath}trojangrpc#${email}\n"
		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${currentAdd}:${currentDefaultPort}?encryption=none&peer=${currentHost}&security=tls&type=grpc&sni=${currentHost}&alpn=h2&path=${currentPath}trojangrpc&serviceName=${currentPath}trojangrpc#${email}
EOF
		#echoContent yellow " ---> 二维码 Trojan gRPC(TLS)"
		#echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${currentAdd}%3a${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dtls%26peer%3d${currentHost}%26type%3Dgrpc%26sni%3d${currentHost}%26path%3D${currentPath}trojangrpc%26alpn%3Dh2%26serviceName%3D${currentPath}trojangrpc%23${email}\n"
	fi

}


# 账号
showAccounts() {
	readInstallType
	readInstallProtocolType
	readConfigHostPathUUID
	echoContent skyBlue "\n进度 $1/${totalProgress} : 账号"
	local show

	clear
	echoContent skyBlue "\n功能 : 账号管理"
	echoContent red "\n=============================================================="
	echoContent yellow "# 每次删除、添加账号后，需要重新查看订阅生成订阅\n"
	echoContent yellow "1. VLESS TCP TLS/XTLS-direct/splice"
	echoContent yellow "2. VLESS WS TLS CDN"
	echoContent yellow "3. VMess WS TLS CDN"
	echoContent yellow "4. VLESS gRPC TLS CDN"
	echoContent yellow "5. Trojan TLS"
	echoContent yellow "6. Trojan gRPC TLS"
	echoContent red "=============================================================="



	read -p "请选择 : " select001

	# VLESS TCP
	if [[ -n "${configPath}" ]]; then
		show=1

		case $select001 in
		1)
			# VLESS TCP
			if echo "${currentInstallProtocolType}" | grep -q trojan; then
				echoContent skyBlue "===================== Trojan TCP TLS/XTLS-direct/splice ======================\n"
				jq .inbounds[0].settings.clients ${configPath}02_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
					echoContent skyBlue "\n ---> 帐号: $(echo "${user}" | jq -r .email)"
					defaultBase64Code trojanTCPXTLS "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .password)"
				done

			else
				echoContent skyBlue "===================== VLESS TCP TLS/XTLS-direct/splice ======================\n"
				jq .inbounds[0].settings.clients ${configPath}02_VLESS_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
					echoContent skyBlue "\n ---> 帐号: $(echo "${user}" | jq -r .email)"
					echoContent skyBlue " ---> expired date: $(echo "${user}" | jq -r .expired)"
					echo
					defaultBase64Code vlesstcp "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)"
				done
			fi
			;;
		2)
			# VLESS WS
			if echo ${currentInstallProtocolType} | grep -q 1; then
				echoContent skyBlue "\n================================ VLESS WS TLS CDN ================================\n"

				jq .inbounds[0].settings.clients ${configPath}03_VLESS_WS_inbounds.json | jq -c '.[]' | while read -r user; do
					echoContent skyBlue "\n ---> 帐号: $(echo "${user}" | jq -r .email)"
					echo
					local path="${currentPath}ws"
					#	if [[ ${coreInstallType} == "1" ]]; then
					#		echoContent yellow "Xray的0-RTT path后面会有，不兼容以v2ray为核心的客户端，请手动删除后使用\n"
					#		path="${currentPath}ws"
					#	fi
					defaultBase64Code vlessws "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)"
				done
			fi
			;;
		3)
			# VMess WS
			if echo ${currentInstallProtocolType} | grep -q 3; then
				echoContent skyBlue "\n================================ VMess WS TLS CDN ================================\n"
				local path="${currentPath}vws"
				if [[ ${coreInstallType} == "1" ]]; then
					path="${currentPath}vws"
				fi
				jq .inbounds[0].settings.clients ${configPath}05_VMess_WS_inbounds.json | jq -c '.[]' | while read -r user; do
					echoContent skyBlue "\n ---> 帐号:$(echo "${user}" | jq -r .email)"
					echo
					defaultBase64Code vmessws "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)"
				done
			fi
			;;
		4)
			# VLESS grpc
			if echo ${currentInstallProtocolType} | grep -q 5; then
				echoContent skyBlue "\n=============================== VLESS gRPC TLS CDN ===============================\n"
				echoContent red "\n --->gRPC处于测试阶段，可能对你使用的客户端不兼容，如不能使用请忽略"
				#			local serviceName
				#			serviceName=$(jq -r .inbounds[0].streamSettings.grpcSettings.serviceName ${configPath}06_VLESS_gRPC_inbounds.json)
				jq .inbounds[0].settings.clients ${configPath}06_VLESS_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
					echoContent skyBlue "\n ---> 帐号: $(echo "${user}" | jq -r .email)"
					echo
					defaultBase64Code vlessgrpc "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)"
				done
			fi
			;;
		esac
	fi
	case $select001 in
	5)
		# trojan tcp
		if echo ${currentInstallProtocolType} | grep -q 4; then
			echoContent skyBlue "\n==================================  Trojan TLS  ==================================\n"
			jq .inbounds[0].settings.clients ${configPath}04_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> 帐号: $(echo "${user}" | jq -r .email)"

				defaultBase64Code trojan "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .password)"
			done
		fi
		;;
	6)
		# trojan gRPC TLS
		if echo ${currentInstallProtocolType} | grep -q 2; then
			echoContent skyBlue "\n================================  Trojan gRPC TLS  ================================\n"
			echoContent red "\n --->gRPC处于测试阶段，可能对你使用的客户端不兼容，如不能使用请忽略"
			#		local serviceName=
			#		serviceName=$(jq -r .inbounds[0].streamSettings.grpcSettings.serviceName ${configPath}04_trojan_gRPC_inbounds.json)
			jq .inbounds[0].settings.clients ${configPath}04_trojan_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> 帐号: $(echo "${user}" | jq -r .email)"
				echo
				defaultBase64Code trojangrpc "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .password)"
			done
		fi
		;;
	esac

	if [[ -z ${show} ]]; then
		echoContent red " ---> 未安装"
	fi
}

# 订阅
subscribe() {
	if [[ -n "${configPath}" ]]; then
		echoContent skyBlue "-------------------------备注---------------------------------"
		echoContent yellow "# 查看订阅时会重新生成订阅"
		echoContent yellow "# 每次添加、删除账号需要重新查看订阅"
		rm -rf /etc/v2ray-agent/subscribe/*
		rm -rf /etc/v2ray-agent/subscribe_tmp/*
		showAccounts >/dev/null
		mv /etc/v2ray-agent/subscribe_tmp/* /etc/v2ray-agent/subscribe/

		if [[ -n $(ls /etc/v2ray-agent/subscribe/) ]]; then
			find /etc/v2ray-agent/subscribe/* | while read -r email; do
				email=$(echo "${email}" | awk -F "[b][e][/]" '{print $2}')

				local base64Result
				base64Result=$(base64 -w 0 "/etc/v2ray-agent/subscribe/${email}")
				echo "${base64Result}" >"/etc/v2ray-agent/subscribe/${email}"
				echoContent skyBlue "--------------------------------------------------------------"
				echoContent yellow "email:${email}\n"
				local currentDomain=${currentHost}

				if [[ -n "${currentDefaultPort}" && "${currentDefaultPort}" != "443" ]]; then
					currentDomain="${currentHost}:${currentDefaultPort}"
				fi

				echoContent yellow "url:https://${currentDomain}/s/${email}\n"
				echoContent yellow "在线二维码:https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=https://${currentDomain}/s/${email}\n"
				echo "https://${currentDomain}/s/${email}" | qrencode -s 10 -m 1 -t UTF8
				echoContent skyBlue "--------------------------------------------------------------"
			done
		fi
	else
		echoContent red " ---> 未安装"
	fi
}

# 添加用户
addUser() {

	echoContent yellow "添加新用户后，需要重新查看订阅"
	#read -r -p "请输入要添加的用户数量:" userNum
	userNum=1
	echo
	if [[ -z ${userNum} || ${userNum} -le 0 ]]; then
		echoContent red " ---> 输入有误，请重新输入"
		exit 0
	fi

	# 生成用户
	if [[ "${userNum}" == "1" ]]; then
		customUUID
		customUserEmail
	fi

	while [[ ${userNum} -gt 0 ]]; do
		local users=
		((userNum--)) || true
		if [[ -n "${currentCustomUUID}" ]]; then
			uuid=${currentCustomUUID}
		else
			uuid=$(${ctlPath} uuid)
		fi

		if [[ -n "${currentCustomEmail}" ]]; then
			email=${currentCustomEmail}
		else
			email=${currentHost}_${uuid}
		fi

		#	兼容v2ray-core

		read -p "Expired (days): " masaaktif
		exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
		#echo "exp= $exp"

		users="{\"id\":\"${uuid}\",\"flow\":\"xtls-rprx-direct\",\"email\":\"${email}\",\"expired\":\"${exp}\",\"alterId\":0}"

		if [[ "${coreInstallType}" == "2" ]]; then
			users="{\"id\":\"${uuid}\",\"email\":\"${email}\",\"alterId\":0}"
		fi

		if echo ${currentInstallProtocolType} | grep -q 0; then
			local vlessUsers="${users//\,\"alterId\":0/}"

			local vlessTcpResult
			vlessTcpResult=$(jq -r ".inbounds[0].settings.clients += [${vlessUsers}]" ${configPath}${frontingType}.json)
			echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
		fi

		if echo ${currentInstallProtocolType} | grep -q trojan; then
			local trojanXTLSUsers="${users//\,\"alterId\":0/}"
			trojanXTLSUsers=${trojanXTLSUsers//"id"/"password"}

			local trojanXTLSResult
			trojanXTLSResult=$(jq -r ".inbounds[0].settings.clients += [${trojanXTLSUsers}]" ${configPath}${frontingType}.json)
			echo "${trojanXTLSResult}" | jq . >${configPath}${frontingType}.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 1; then
			local vlessUsers="${users//\,\"alterId\":0/}"
			vlessUsers="${vlessUsers//\"flow\":\"xtls-rprx-direct\"\,/}"
			local vlessWsResult
			vlessWsResult=$(jq -r ".inbounds[0].settings.clients += [${vlessUsers}]" ${configPath}03_VLESS_WS_inbounds.json)
			echo "${vlessWsResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then
			local trojangRPCUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			trojangRPCUsers="${trojangRPCUsers//\,\"alterId\":0/}"
			trojangRPCUsers=${trojangRPCUsers//"id"/"password"}

			local trojangRPCResult
			trojangRPCResult=$(jq -r ".inbounds[0].settings.clients += [${trojangRPCUsers}]" ${configPath}04_trojan_gRPC_inbounds.json)
			echo "${trojangRPCResult}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then
			local vmessUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"

			local vmessWsResult
			vmessWsResult=$(jq -r ".inbounds[0].settings.clients += [${vmessUsers}]" ${configPath}05_VMess_WS_inbounds.json)
			echo "${vmessWsResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			local vlessGRPCUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			vlessGRPCUsers="${vlessGRPCUsers//\,\"alterId\":0/}"

			local vlessGRPCResult
			vlessGRPCResult=$(jq -r ".inbounds[0].settings.clients += [${vlessGRPCUsers}]" ${configPath}06_VLESS_gRPC_inbounds.json)
			echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then
			local trojanUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			trojanUsers="${trojanUsers//id/password}"
			trojanUsers="${trojanUsers//\,\"alterId\":0/}"

			local trojanTCPResult
			trojanTCPResult=$(jq -r ".inbounds[0].settings.clients += [${trojanUsers}]" ${configPath}04_trojan_TCP_inbounds.json)
			echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
		fi
	done

	reloadCore
	echoContent green " ---> 添加完成"
	manageAccount 1
}

# 移除用户
removeUser() {

	if echo ${currentInstallProtocolType} | grep -q 0 || echo ${currentInstallProtocolType} | grep -q trojan; then
		jq -r -c .inbounds[0].settings.clients[].email ${configPath}${frontingType}.json | awk '{print NR""":"$0}'
		read -r -p "请选择要删除的用户编号[仅支持单个删除]:" delUserIndex
		if [[ $(jq -r '.inbounds[0].settings.clients|length' ${configPath}${frontingType}.json) -lt ${delUserIndex} ]]; then
			echoContent red " ---> 选择错误"
		else
			delUserIndex=$((delUserIndex - 1))
			local vlessTcpResult
			vlessTcpResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}${frontingType}.json)
			echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
		fi
	fi
	if [[ -n "${delUserIndex}" ]]; then
		if echo ${currentInstallProtocolType} | grep -q 1; then
			local vlessWSResult
			vlessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}03_VLESS_WS_inbounds.json)
			echo "${vlessWSResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then
			local trojangRPCUsers
			trojangRPCUsers=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_gRPC_inbounds.json)
			echo "${trojangRPCUsers}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then
			local vmessWSResult
			vmessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}05_VMess_WS_inbounds.json)
			echo "${vmessWSResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			local vlessGRPCResult
			vlessGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}06_VLESS_gRPC_inbounds.json)
			echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then
			local trojanTCPResult
			trojanTCPResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_TCP_inbounds.json)
			echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
		fi

		reloadCore
	fi
	manageAccount 1
}


# 移除过期的用户
removeExpUser() {

	if echo ${currentInstallProtocolType} | grep -q 0 || echo ${currentInstallProtocolType} | grep -q trojan; then
		jq -r -c .inbounds[0].settings.clients[].email ${configPath}${frontingType}.json | awk '{print NR""":"$0}'
		#read -r -p "请选择要删除的用户编号[仅支持单个删除]:" delUserIndex
		delUserIndex=$num1

		if [[ $(jq -r '.inbounds[0].settings.clients|length' ${configPath}${frontingType}.json) -lt ${delUserIndex} ]]; then
			echoContent red " ---> 选择错误"
		else
			delUserIndex=$((delUserIndex - 1))
			local vlessTcpResult
			vlessTcpResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}${frontingType}.json)
			echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
		fi
	fi
	if [[ -n "${delUserIndex}" ]]; then
		if echo ${currentInstallProtocolType} | grep -q 1; then
			local vlessWSResult
			vlessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}03_VLESS_WS_inbounds.json)
			echo "${vlessWSResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then
			local trojangRPCUsers
			trojangRPCUsers=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_gRPC_inbounds.json)
			echo "${trojangRPCUsers}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then
			local vmessWSResult
			vmessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}05_VMess_WS_inbounds.json)
			echo "${vmessWSResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			local vlessGRPCResult
			vlessGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}06_VLESS_gRPC_inbounds.json)
			echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then
			local trojanTCPResult
			trojanTCPResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_TCP_inbounds.json)
			echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
		fi
		sleep 1
		reloadCore
		sleep 1
		echo "remove id done"
	fi

}


removeExpUser1(){

	echoContent skyBlue "\n功能 : 已到期账号"
	echoContent red "\n=============================================================="
	echoContent yellow "1.查看已到期账号"
	echoContent yellow "2.删除已到期账号"
	echoContent red "=============================================================="
	read -r -p "请输入:" select01

	case $select01 in 
	1)	
		echoContent skyBlue "===================== 查看已到期账号 ======================\n"
		now=$(date +%Y-%m-%d)
		num1=1
		jq .inbounds[0].settings.clients ${configPath}02_VLESS_TCP_inbounds.json | jq -c '.[]' | 
		while read -r user
		do
			#echo $num1
			echoContent skyBlue "$num1 ---> 帐号: $(echo "${user}" | jq -r .email)"
			#echo $user
			#echoContent skyBlue " ---> expired date: $(echo "${user}" | jq -r .expired)"
			exp=$(echo "${user}" | jq -r .expired)
			echoContent skyBlue " ---> Expired Date: $exp"

			
			#echo "now= $now"

			d1=$(date -d "$exp" +%s)
			#echo "d1= $d1"

			d2=$(date -d "$now" +%s)
			#echo "d2= $d2"

			exp2=$(( (d1 - d2) / 86400 ))
			echo -e "剩余天数= $exp2"

			if [[ $exp2 -lt 0 ]]
			then
				echoContent red "id is expired"	
				echo ""
			else
				echoContent green "id is active"
				echo ""
			fi
			num1=`expr $num1 + 1`
		done
		;;
	2)
		echoContent skyBlue "===================== 删除已到期账号 ======================\n"
		now=$(date +%Y-%m-%d)
		num1=1
		jq .inbounds[0].settings.clients ${configPath}02_VLESS_TCP_inbounds.json | jq -c '.[]' | 
		while read -r user
		do
			#echo $num1
			echoContent skyBlue "$num1 ---> 帐号: $(echo "${user}" | jq -r .email)"
			#echo $user
			#echoContent skyBlue " ---> expired date: $(echo "${user}" | jq -r .expired)"
			exp=$(echo "${user}" | jq -r .expired)
			echoContent skyBlue " ---> Expired Date: $exp"

			#now=$(date +%Y-%m-%d)
			#echo "now= $now"

			d1=$(date -d "$exp" +%s)
			#echo "d1= $d1"

			d2=$(date -d "$now" +%s)
			#echo "d2= $d2"

			exp2=$(( (d1 - d2) / 86400 ))
			#echo "exp2= $exp2"

			if [[ $exp2 -lt 0 ]]
			then
				echoContent red "id is expired"	
				echo ""
				removeExpUser2
				#num1=1
			else
				echoContent green "id is active"
				echo ""
				num1=`expr $num1 + 1`
			fi
			
		done
		;;
	esac

	echo ""
}

# 移除过期的用户
removeExpUser2() {

	if echo ${currentInstallProtocolType} | grep -q 0 || echo ${currentInstallProtocolType} | grep -q trojan; then
		jq -r -c .inbounds[0].settings.clients[].email ${configPath}${frontingType}.json | awk '{print NR""":"$0}'
		#read -r -p "请选择要删除的用户编号[仅支持单个删除]:" delUserIndex
		delUserIndex=$num1

		if [[ $(jq -r '.inbounds[0].settings.clients|length' ${configPath}${frontingType}.json) -lt ${delUserIndex} ]]; then
			echoContent red " ---> 选择错误"
		else
			delUserIndex=$((delUserIndex - 1))
			local vlessTcpResult
			vlessTcpResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}${frontingType}.json)
			echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
		fi
	fi
	if [[ -n "${delUserIndex}" ]]; then
		if echo ${currentInstallProtocolType} | grep -q 1; then
			local vlessWSResult
			vlessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}03_VLESS_WS_inbounds.json)
			echo "${vlessWSResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then
			local trojangRPCUsers
			trojangRPCUsers=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_gRPC_inbounds.json)
			echo "${trojangRPCUsers}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then
			local vmessWSResult
			vmessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}05_VMess_WS_inbounds.json)
			echo "${vmessWSResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			local vlessGRPCResult
			vlessGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}06_VLESS_gRPC_inbounds.json)
			echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then
			local trojanTCPResult
			trojanTCPResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_TCP_inbounds.json)
			echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
		fi
		sleep 1
		reloadCore
		sleep 1
		echo "Remove Expired User Done"
	fi
}

# 查看、检查日志
checkLog() {
	if [[ -z ${configPath} ]]; then
		echoContent red " ---> 没有检测到安装目录，请执行脚本安装内容"
	fi
	local logStatus=false
	if grep -q "access" ${configPath}00_log.json; then
		logStatus=true
	fi

	echoContent skyBlue "\n功能 : 查看日志"
	echoContent red "\n=============================================================="
	echoContent yellow "# 建议仅调试时打开access日志\n"

	if [[ "${logStatus}" == "false" ]]; then
		echoContent yellow "1.打开access日志"
	else
		echoContent yellow "1.关闭access日志"
	fi

	echoContent yellow "2.监听access日志"
	echoContent yellow "3.监听error日志"
	echoContent yellow "4.查看证书定时任务日志"
	echoContent yellow "5.查看证书安装日志"
	echoContent yellow "6.清空日志"
	echoContent red "=============================================================="

	read -r -p "请选择:" selectAccessLogType
	local configPathLog=${configPath//conf\//}

	case ${selectAccessLogType} in
	1)
		if [[ "${logStatus}" == "false" ]]; then
			cat <<EOF >${configPath}00_log.json
{
  "log": {
  	"access":"${configPathLog}access.log",
    "error": "${configPathLog}error.log",
    "loglevel": "debug"
  }
}
EOF
		elif [[ "${logStatus}" == "true" ]]; then
			cat <<EOF >${configPath}00_log.json
{
  "log": {
    "error": "${configPathLog}error.log",
    "loglevel": "warning"
  }
}
EOF
		fi
		reloadCore
		checkLog 1
		;;
	2)
		tail -f ${configPathLog}access.log
		;;
	3)
		tail -f ${configPathLog}error.log
		;;
	4)
		tail -n 100 /etc/v2ray-agent/crontab_tls.log
		;;
	5)
		tail -n 100 /etc/v2ray-agent/tls/acme.log
		;;
	6)
		echo >${configPathLog}access.log
		echo >${configPathLog}error.log
		;;
	esac
}


renew() {

	echo ""
	echoContent skyBlue "========================================================="
	if echo ${currentInstallProtocolType} | grep -q 0 || echo ${currentInstallProtocolType} | grep -q trojan; then

		jq -r -c .inbounds[0].settings.clients[].email ${configPath}${frontingType}.json | awk '{print NR""":"$0}'
		echoContent skyBlue "========================================================="
		
		read -r -p "请选择要更新日期的用户:" UserIndex

		if [[ $(jq -r '.inbounds[0].settings.clients|length' ${configPath}${frontingType}.json) -lt ${UserIndex} ]]; then
			
			echoContent red " ---> 选择错误"
		else
			UserIndex=$((UserIndex - 1))
			local vlessTcpResult
			vlessTcpResult=$(jq -r 'del(.inbounds[0].settings.clients['${UserIndex}'])' ${configPath}${frontingType}.json)
			exp1=$(jq .inbounds[0].settings.clients[$UserIndex].expired ${configPath}${frontingType}.json)
			user1=$(jq .inbounds[0].settings.clients[$UserIndex].email ${configPath}${frontingType}.json)
			#echo ${#exp1}
			user1=${user1:1:(${#user1}-2)}
			exp1=${exp1:1:(${#exp1}-2)}
			clear
			echo ""
			echoContent skyBlue "User ID              : $user1"
			echoContent skyBlue "Current expired date : $exp1"
			echo ""
			read -r -p "Extend how many (day) ? :" day_extend

			t1=$(date -d "$exp1 +$day_extend day " +%Y-%m-%d)

			###echo $vlessTcpResult
			###name1=$(jq -r '.inbounds[0].settings.clients)' ${configPath}${frontingType}.json)
			###echo ${configPath}${frontingType}.json
			#exp1= cat ${configPath}${frontingType}.json | jq '.inbounds[0].settings.clients['${UserIndex}'].expired' 
			#val2=$(jq ".inbounds[0].settings.clients['${UserIndex}'].expired" ${configPath}${frontingType}.json)
			#echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
			#cat ${configPath}${frontingType}.json | jq 'to_entries | map(if .key == "expired" then . + {"value":"2022-06-10"} else .end) | from_entries'

			#echo "$exp1"
			jq '.inbounds[0].settings.clients['${UserIndex}'].expired = "'$t1'"' ${configPath}${frontingType}.json | sponge ${configPath}${frontingType}.json
			#echo $val2 
			#jq '.inbounds[0].settings.clients['${UserIndex}'].expired="new value"' ${configPath}${frontingType}.json
			#echo $val2
			echo ""
			echoContent green "User ID            : $user1"
			echoContent green "Date Latest Update : $t1"
			echoContent green "Renew Done"
			#vlessTcpResult=$(jq -r ".inbounds[0].settings.clients += [${vlessUsers}]" ${configPath}${frontingType}.json)

			#exp1= cat ${configPath}${frontingType}.json | jq '.inbounds[0].settings.clients['${UserIndex}'].expired' 
			
			#echo "${jq '.inbounds[0].settings.clients['${UserIndex}'].expired="new value"' ${configPath}${frontingType}.json}"
			#read -r -p "extend day:" valday
			#d1=$(date -d "$exp1" +%s)
		#	echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
		fi
	fi
	manageAccount
}

install2(){
	echo "安装 moreutils 包"
	sudo apt-get update
	sudo apt-get install moreutils
}


# 账号管理
manageAccount() {
	echoContent skyBlue "\n功能 : 账号管理"
	echoContent red "\n=============================================================="
	echoContent yellow "# 每次删除、添加账号后，需要重新查看订阅生成订阅\n"
	echoContent yellow " 1.查看账号 ---------- > Cheak All User Config "
	echoContent yellow " 2.更新账号日期 ------ > Renew ID "
	echoContent yellow " 3.添加账号 ---------- > Add User ID "
	echoContent yellow " 4.删除账号 ---------- > Delete User ID "
	echoContent yellow " 5.新服务器必装脚本 -- > Install Script For New Server Only "
	echoContent yellow " 9.删除已到期账号 ---- > Remove Expired ID "
	echoContent yellow "18.查看日志 ---------- > Cheak User Login "
	echo ""
	echoContent red "=============================================================="



	read -r -p "请输入:" manageAccountStatus
	if [[ "${manageAccountStatus}" == "1" ]]; then
		showAccounts 1
	elif [[ "${manageAccountStatus}" == "2" ]]; then
		renew
	elif [[ "${manageAccountStatus}" == "3" ]]; then
		addUser
	elif [[ "${manageAccountStatus}" == "4" ]]; then
		removeUser
	elif [[ "${manageAccountStatus}" == "5" ]]; then
		install2
	elif [[ "${manageAccountStatus}" == "9" ]]; then
		removeExpUser1
	elif [[ "${manageAccountStatus}" == "18" ]]; then
		checkLog 1
	else
		echoContent red " ---> 选择错误"
	fi
}


#=======================================================================================================
#=======================================================================================================
#=======================================================================================================

initVar "$1"
readInstallType
readInstallProtocolType
readConfigHostPathUUID

manageAccount




#exp="2022-05-08"
#echo "exp= $exp"

#now=$(date +%Y-%m-%d)
#echo "now= $now"

#d1=$(date -d "$exp" +%s)
#echo "d1= $d1"

#d2=$(date -d "$now" +%s)
#echo "d2= $d2"

#exp2=$(( (d1 - d2) / 86400 ))
#echo "exp2= $exp2"

#read -p "Expired (days): " masaaktif
#exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
#echo "exp= $exp"
