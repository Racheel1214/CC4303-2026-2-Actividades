import socket
import collections
from dnslib import DNSRecord
from dnslib.dns import RR, A, QTYPE, CLASS
import dnslib

IP_VM = "127.0.0.1"        
PORT = 8000                
ROOT_IP = "198.41.0.4"
historial = []   
resolved_ips = {}          

def top_3_dominios():
    if not historial:
        return set()
    cont = collections.Counter(historial)
    top3 = cont.most_common(3)
    dominios = {}
    i = 0
    for dominio, cant in top3:
        dominios[i] = dominio
        i += 1
    return dominios.values()

def print_dns_reply_elements(dnslib_reply):
    print(">>--------------- HEADER SECTION ---------------<<\n")
    print("----------- dnslib_reply.header -----------\n{}\n".format(dnslib_reply.header))
    
    qr_flag = dnslib_reply.header.get_qr()
    print("-> qr_flag = {}".format(qr_flag))

    number_of_query_elements = dnslib_reply.header.q
    print("-> number_of_query_elements = {}".format(number_of_query_elements))

    number_of_answer_elements = dnslib_reply.header.a
    print("-> number_of_answer_elements = {}".format(number_of_answer_elements))

    number_of_authority_elements = dnslib_reply.header.auth
    print("-> number_of_authority_elements = {}".format(number_of_authority_elements))

    number_of_additional_elements = dnslib_reply.header.ar
    print("-> number_of_additional_elements = {}".format(number_of_additional_elements))
    print(">>----------------------------------------------<<\n")

    print(">>---------------- QUERY SECTION ---------------<<\n")
    all_querys = dnslib_reply.questions  
    print("-> all_querys = {}".format(all_querys))

    first_query = dnslib_reply.get_q()  
    print("-> first_query = {}".format(first_query))

    domain_name_in_query = first_query.get_qname()  
    print("-> domain_name_in_query = {}".format(domain_name_in_query))

    query_class = CLASS.get(first_query.qclass)
    print("-> query_class = {}".format(query_class))

    query_type = QTYPE.get(first_query.qtype)
    print("-> query_type = {}".format(query_type))
    print(">>----------------------------------------------<<\n")

    print(">>---------------- ANSWER SECTION --------------<<\n")
    if number_of_answer_elements > 0:
        all_resource_records = dnslib_reply.rr  
        print("-> all_resource_records = {}".format(all_resource_records))

        first_answer = dnslib_reply.get_a()  
        print("-> first_answer = {}".format(first_answer))

        domain_name_in_answer = first_answer.get_rname()  
        print("-> domain_name_in_answer = {}".format(domain_name_in_answer))

        answer_class = CLASS.get(first_answer.rclass)
        print("-> answer_class = {}".format(answer_class))

        answer_type = QTYPE.get(first_answer.rtype)
        print("-> answer_type = {}".format(answer_type))

        answer_rdata = first_answer.rdata  
        print("-> answer_rdata = {}".format(answer_rdata))
    else:
        print("-> number_of_answer_elements = {}".format(number_of_answer_elements))
    print(">>----------------------------------------------<<\n")

    print(">>-------------- AUTHORITY SECTION -------------<<\n")
    if number_of_authority_elements > 0:
        authority_section_list = dnslib_reply.auth  
        print("-> authority_section_list = {}".format(authority_section_list))

        if len(authority_section_list) > 0:
            authority_section_RR_0 = authority_section_list[0]  
            print("-> authority_section_RR_0 = {}".format(authority_section_RR_0))

            auth_type = QTYPE.get(authority_section_RR_0.rtype)
            print("-> auth_type = {}".format(auth_type))

            auth_class = CLASS.get(authority_section_RR_0.rclass)
            print("-> auth_class = {}".format(auth_class))

            auth_time_to_live = authority_section_RR_0.ttl
            print("-> auth_time_to_live = {}".format(auth_time_to_live))

            authority_section_0_rdata = authority_section_RR_0.rdata
            print("-> authority_section_0_rdata = {}".format(authority_section_0_rdata))

            if isinstance(authority_section_0_rdata, dnslib.dns.SOA):
                primary_name_server = authority_section_0_rdata.get_mname()
                print("-> primary_name_server = {}".format(primary_name_server))
            elif isinstance(authority_section_0_rdata, dnslib.dns.NS):
                name_server_domain = authority_section_0_rdata
                print("-> name_server_domain = {}".format(name_server_domain))
    else:
        print("-> number_of_authority_elements = {}".format(number_of_authority_elements))
    print(">>----------------------------------------------<<\n")

    print(">>------------- ADDITIONAL SECTION -------------<<\n")
    if number_of_additional_elements > 0:
        additional_records = dnslib_reply.ar  
        print("-> additional_records = {}".format(additional_records))

        first_additional_record = additional_records[0]  
        print("-> first_additional_record = {}".format(first_additional_record))

        ar_class = CLASS.get(first_additional_record.rclass)
        print("-> ar_class = {}".format(ar_class))

        ar_type = QTYPE.get(first_additional_record.rtype)
        print("-> ar_type = {}".format(ar_type))

        if ar_type == 'A':  
            first_additional_record_rname = first_additional_record.rname
            print("-> first_additional_record_rname = {}".format(first_additional_record_rname))

            first_additional_record_rdata = first_additional_record.rdata
            print("-> first_additional_record_rdata = {}".format(first_additional_record_rdata))
    else:
        print("-> number_of_additional_elements = {}".format(number_of_additional_elements))
    print(">>----------------------------------------------<<\n")

def resolver(mensaje_consulta: bytes, ip_addr = ROOT_IP, ns_name = ".", is_client_query = True) -> bytes:
    try:
        query_dns = DNSRecord.parse(mensaje_consulta)
        qname = str(query_dns.get_q().get_qname())
    except Exception as e:
        print(f"Error al parsear consulta inicial: {e}")
        return b""

    if is_client_query and ip_addr == ROOT_IP and ns_name == ".":
        print_dns_reply_elements(query_dns)
        historial.append(qname)
        if len(historial) > 20:
            historial.pop(0)

        top_3 = top_3_dominios()

        if qname in top_3 and qname in resolved_ips:
            cache_ip = resolved_ips[qname]
            print(f"(debug) [CACHÉ] Dominio '{qname}' se encuentra en el caché. Respondiendo con la IP almacenada '{cache_ip}'")
            respuesta = query_dns.reply()
            respuesta.add_answer(RR(qname, QTYPE.A, rdata=A(cache_ip), ttl=60))
            return respuesta.pack()

    print(f"(debug) Consultando '{qname}' a '{ns_name}' con dirección IP '{ip_addr}'")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0) 

    # Parte 4-A
    try:
        sock.sendto(mensaje_consulta, (ip_addr, 53))
        response_bytes, _ = sock.recvfrom(4096)
    except Exception:
        return b""
    finally:
        sock.close()

    try:
        d = DNSRecord.parse(response_bytes)
    except Exception:
        return b""
    
    # Parte 4-B
    a_in_answer = False
    for rr in d.rr:
        if int(rr.rtype) == 1:  
            a_in_answer = True
            break
            
    if a_in_answer:
        if is_client_query:
            for rr in d.rr:
                if int(rr.rtype) == 1:
                    resolved_ips[qname] = str(rr.rdata)
                    break
        return response_bytes
    
    # Parte 4-C
    ns_in_authority = False
    ns_in_auth = []
    for rr in d.auth:
        if int(rr.rtype) == 2:  
            ns_in_authority = True
            ns_in_auth.append(str(rr.rdata))

    if ns_in_authority:
        additional_ips = []
        for rr in d.ar:
            if int(rr.rtype) == 1:  
                additional_ips.append((str(rr.rname), str(rr.rdata)))

        if additional_ips:
            target_ns_name, target_ns_ip = additional_ips[0]
            return resolver(mensaje_consulta, target_ns_ip, target_ns_name, is_client_query)

        elif ns_in_auth:
            target_ns_name = ns_in_auth[0]
            target_ns_name_str = str(target_ns_name)
            if target_ns_name_str.endswith('.'):
                target_ns_name_str = target_ns_name_str[:-1]
            
            ns_query = DNSRecord.question(target_ns_name_str)
            
            print(f"(debug) Intentando resolver IP del Name Server '{target_ns_name_str}' de forma recursiva.")
            ns_resolve_bytes = resolver(bytes(ns_query.pack()), is_client_query = False)
            
            resolved_ip = None
            if ns_resolve_bytes:
                ns_dns = DNSRecord.parse(ns_resolve_bytes)
                for rr in ns_dns.rr:
                    if int(rr.rtype) == 1:
                        resolved_ip = str(rr.rdata)
                        break
            
            if resolved_ip:
                return resolver(mensaje_consulta, resolved_ip, target_ns_name_str, is_client_query)
            
    return b""

def iniciar_servidor():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((IP_VM, PORT))
        print(f"Servidor DNS escuchando en {IP_VM}:{PORT}...")
        print("Esperando consultas de clientes...\n")

        while True:
            data, client_address = server_socket.recvfrom(4096)
            print("----------------------------------------------------")
            print(f"Consulta recibida de {client_address}")
            respuesta_bytes = resolver(data)
            
            if respuesta_bytes:
                server_socket.sendto(respuesta_bytes, client_address)
            else:
                print("No se pudo resolver la consulta recibida.")
    except Exception as e:
        print(f"Error en el servidor: {e}")
    finally:
        server_socket.close()
        print("Socket cerrado.")

if __name__ == "__main__":
    iniciar_servidor()