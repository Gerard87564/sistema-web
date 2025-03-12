#!/bin/bash

menu () {
	echo "Quina tasca vols reaalitzar?"
	echo "1) Crear nota"
	echo "2) Modificar nota"
	echo "3) Eliminar nota"
	echo "4) Mostrar notes del fitxer"
	echo "5) Cerca, filtratge i ordenació de notes"
	echo "6) Copies de seguretat"
	echo "7) Sortir"
}

function crearNota() {
	idNota=$1
	echo "Escriu un titol per la nota: "
	read titol
	echo "$idNota ==== $titol ====" >> notes.txt
	
	echo "Escriu el contingut de la nota (clica Crtl+D per acabar): "
	cat >> notes.txt
	echo "Escriu la firma de la nota: "
	read firma
	echo "====$firma" >> notes.txt
	
	data=$(date +"%d-%m-%Y")
	dataHora="$data $(date +"%H:%M")"
	
	echo "-$dataHora" >> notes.txt
	echo "====Fi" >> notes.txt
	
	echo "Nota guardada!"
}

function modificarNota() {
	echo "Escriu la id de la nota a modificar: "
	read id
	
	if [ $(ls -t notes_backup_*.txt | wc -l) -ge 3 ]; then
		echo "S'ha arribat al maxim de copies..."
	else 
		cp notes.txt "notes_backup_$(date +"%Y%m%d_%H%M%S").txt"
	fi
	
	echo "Que vols modificar?"
	echo "1) Titol"
	echo "2) Contingut"
	read option
	
	case $option in
		1)
		     titol_actual=$(grep "^$id ==== " notes.txt | awk -F "====" '{print $2}' | sed 's/^ *//;s/ *$//')
            
		    if [ -z "$titol_actual" ]; then
			echo "No s'ha trobat cap nota amb aquesta ID."
			return
		    fi
		    
		    echo "Escriu el nou títol: "
		    read titol_nou
		    sed -i "s|^$id ==== $titol_actual ====|$id ==== $titol_nou ====|" notes.txt 
		;;
		
		2)
	     	    titol_actual=$(grep "^$id ==== " notes.txt | awk -F "====" '{print $2}' | sed 's/^ *//;s/ *$//')
		    temp_file=$(mktemp)
		    
		    cat > "$temp_file"
		    sed -i "/^$id ==== /,/^$/d" notes.txt
		    
		    echo "$id ==== $titol_actual ====" >> notes.txt
		    cat "$temp_file" >> notes.txt
		    echo "Escriu la firma de la nota: "
		    read firma
		    echo "====$firma" >> notes.txt

		    data=$(date +"%d-%m-%Y")
            	    dataHora="$data $(date +"%H:%M")"
		
		    echo "-$dataHora" >> notes.txt
		    echo "====Fi" >> notes.txt
		    
		    rm "$temp_file"
		;;
	esac
			
}

function eliminarNota () {
	echo "Escriu la id de la nota a esborrar: "
	read id
	if ! grep -q "^$id ==== " notes.txt; then
		echo "No existeix la nota..."
	fi
	
	sed -i "/^$id ==== /,/^$/d" notes.txt
}

function mostrarNotes () {
	echo "Id de la nota a mostrar: "
	read id
	
	if ! grep -q "^$id ==== " notes.txt; then
		echo "No existeix la nota..."
	fi
	
        sed -n "/^$id ==== /,/^$/p" notes.txt | sed -E 's/(.*)/\x1b[32m\1\x1b[0m/'

}

function cercaNotes() {
	echo "Perquè vols filtrar?"
	
	echo "1) Titol"
	echo "2) Autor"
	echo "3) Dades"
	echo "4) Paraules clau"
	echo "5) Sortir"
	
	read option
	
	case $option in
		1)
			echo "Escriu el titol a filtrar: "
			read titolFinder
			
			if ! grep -q "==== $titolFinder ====" notes.txt; then
				echo "No existeix la nota..."
			else
				sed -n "/==== $titolFinder ====/,/====Fi/p" notes.txt
			fi
		;;
		
		2)
			echo "Escriu el nom de l'autor:"
			read autor
			
			if ! grep -q "====$autor
			-" notes.txt; then
				echo "No existeix la nota..."
			else
				 sed -n "/====$autor/,/====Fi/p" notes.txt
			fi
		;;
		
		3)
			echo "Escriu el dia de la nota: "
                        read dia
                        
                       	echo "Escriu el mes: "
                       	read mes
                       	
                       	echo "Escriu el any: "
                       	read any
                       	 	
                   	data="$dia-$mes-$any"
                        
                        if ! grep -q "$data" notes.txt; then
                                echo "No es troba cap nota...." 
                        else 
			 	sed -n "/$data/,/====Fi/p" notes.txt
                        fi   
		;;
		
		4)
			echo "Escriu la paraula clau de la nota per filtrar: "
                        read paraulaClau
                        
                        if ! grep -q "$paraulaClau" notes.txt; then
                                echo "No es troba cap nota...." 
                        else 
				 sed -n "/$paraulaClau/,/====Fi/p" notes.txt
                        fi    
		;;
		
		5)
			exit
		;;
	esac
}

function backupsNotes () {
	echo "A quina versió vols restaurar??"
	
	echo "1) 1era"
	echo "2) 2na"
	echo "3) 3era"
	echo "4) Sortir"

	read option

	case $option in
		1)
			last_backup=$(ls -t notes_backup_*.txt | sed -n '1p')

			if [ -z "$last_backup" ]; then
				echo "No es troba cap copia de seguretat..."
		    	else
				cp "$last_backup" notes.txt
			fi				
		;;

		2)
			last_backup=$(ls -t notes_backup_*.txt | sed -n '2p')

			if [ -z "$last_backup" ]; then
				echo "No es troba cap copia de seguretat..."
		    	else
				cp "$last_backup" notes.txt
			fi
		;;
		
		3)
			last_backup=$(ls -t notes_backup_*.txt | sed -n '3p')

			if [ -z "$last_backup" ]; then
				echo "No es troba cap copia de seguretat..."
		    	else
				cp "$last_backup" notes.txt
			fi
		;;
		
		4)
			exit
		;;
	esac
	find . -name "notes_backup_*.txt" -type f -mtime +7 -exec rm {} \;
}

programa () {
	idNota=1
	while true; do
		menu
		
		read option
		case $option in
			1)
				crearNota $idNota
				idNota=$((idNota + 1))
			;;
			
			2)
				modificarNota
			;;
			
			3)
				eliminarNota
			;;
			
			4)
				mostrarNotes
			;;
			
			5)
				cercaNotes
			;;
			
			6)
				backupsNotes
			;;
			
			7)
				exit
			;;
		esac
	done
}

programa
