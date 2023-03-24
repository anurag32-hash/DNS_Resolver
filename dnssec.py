import sys
import dns.resolver
import dns.query
import time
import dns.dnssec

constDS = dns.rdatatype.DS
constSOA = dns.rdatatype.SOA
constRRSIG = dns.rdatatype.RRSIG
constDNSKEY = dns.rdatatype.DNSKEY
constCNAME = dns.rdatatype.CNAME

rootDS = ['19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5',
          '20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d']


def exploreResponse(response, server, dnsType, isSOA):
    if response[0].answer:  # if answer field of response is not empty then return the server
        return [server], isSOA

    if response[0].authority and response[0].authority[0].rdtype == constSOA:  # if authority field of response is non-empty  and is of type SOA then return the server
        isSOA = True
        return [server], isSOA

    if response[0].additional:  # If answer and authority is empty then traverse the additional field and look for other IPs
        res = []
        for i in range(len(response[0].additional)):
            res.append(response[0].additional[i][0].to_text())
        return res, isSOA

    if response[0].authority:  # if anything doesn't hit then it's the CNAME case
        if response[0].authority[0]:
            val = domainResolution(response[0].authority[0][0].to_text(), dnsType)
            if val is None:
                return [], isSOA
            return val, isSOA

    return [], isSOA


def getNextServers(query, server, dnsType):
    isSOA = False
    try:
        newQuery = dns.message.make_query(query, dns.rdatatype.DNSKEY, want_dnssec=True)  # making the TCP query
        response = dns.query.tcp(newQuery, server, timeout=10)
    except:
        return [], None, None, isSOA

    ds, encryptAlgo = None, None

    if response.authority:  # extracting the DS and digest/encryptAlgo
        for i in range(len(response.authority)):
            if response.authority[i].rdtype == constDS:
                ds = response.authority[i][0]
                if response.authority[i][0].digest_type == 1:
                    encryptAlgo = 'sha1'
                if response.authority[i][0].digest_type == 2:
                    encryptAlgo = 'sha256'

    nextServers, SOAflag = exploreResponse([response], server, dnsType, isSOA)  # if there's a valid response, calling the exploreResponse() to get next level servers
    return nextServers, ds, encryptAlgo, SOAflag


def isHashValid(RRset, RRsig, d):
    try:
        dns.dnssec.validate(RRset[0], RRsig[0], d)
    except dns.dnssec.ValidationFailure:
        print('DNSSec verification failed')
        return False
    return True


def isValid(hash, query, dsList, RRsig, RRset):
    verified = False
    for i in range(len(dsList)):  # Step 1 verification
        if str(dsList[i]) == hash:
            verified = True
            break

    if verified is False:
        print('DNSSec verification failed')
        return False

    return isHashValid([RRset], [RRsig], {dns.name.from_text(query): RRset})  # Step 2 verification


def getRRD(domain, server):
    try:  # making the TCP query
        query = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = dns.query.tcp(query, server, timeout=10)
    except:
        return None, None, None

    RRsig, RRset, DNSkey = None, None, None

    if response.answer:  # extracting the RRsig
        for i in range(len(response.answer)):
            if response.answer[i].rdtype == constRRSIG:
                RRsig = response.answer[i]
                break

        for i in range(len(response.answer)):  # extracting the RRset and ZSK
            if response.answer[i].rdtype == constDNSKEY:
                for j in range(len(response.answer[i])):
                    if response.answer[i][j].flags == 257:
                        RRset, DNSkey = response.answer[i], response.answer[i][j]

    return RRsig, RRset, DNSkey


def domainResolution(domain, dnsType):
    dns_domain = dns.name.from_text(domain)
    domainList = str(dns_domain).split('.')[::-1][1::]  # splitting the domain and reversing it
    currServers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241',
                   '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
                   '202.12.27.33']  # root servers
    query = ''
    rootFlag = True
    nextServers, ds, encryptAlgo = None, None, None

    for i in range(len(domainList)):  # traversing the subdomains
        if rootFlag:
            for j in range(len(currServers)):  # traversing the root servers
                RRsig, RRset, DNSkey = getRRD('.', currServers[j])  # getting the RRset, RRsig and ZSK
                if not RRsig or not RRset or not DNSkey:
                    continue
                domainHash = dns.dnssec.make_ds('.', DNSkey, 'sha256')  # creating the hash
                if not isValid(str(domainHash), '.', rootDS, RRsig, RRset):  # validation step
                    continue
                nextServers, ds, encryptAlgo, isSOA = getNextServers(domainList[i] + '.', currServers[j], dnsType)  # getting the next level servers
                if not nextServers:
                    continue
                rootFlag = False
                break

        elif not rootFlag:
            if not currServers:
                break

            for j in range(len(currServers)):  # traversing the current servers
                RRsig, RRset, DNSkey = getRRD(query, currServers[j])  # getting the RRset, RRsig and ZSK
                if RRsig and RRset and DNSkey:
                    break

            if not encryptAlgo or not ds or not DNSkey or not RRsig:  # if either DS, RRsig, ZSK or digest not found then print DNSSEC not supported
                print('DNSSEC not supported')
                return None
            domainHash = dns.dnssec.make_ds(query, DNSkey, encryptAlgo)  # creating the hash
            if not isValid(str(domainHash), query, [ds], RRsig, RRset):  # validation step
                return None

            for k in range(len(currServers)):  # traversing the curr servers to find the next level servers
                nextServers, ds, encryptAlgo, isSOA = getNextServers(domainList[i] + '.' + query, currServers[k], dnsType)
                if isSOA:
                    return nextServers
                if nextServers:
                    break

        query = domainList[i] + '.' + query  # updating the query with new subdomain
        currServers = nextServers

    return currServers


def mydig(domain, dnsType):
    res = domainResolution(domain, dnsType)  # calling the function which will give back the final list of servers
    if res:
        for i in range(len(res)):
            try:  # making the TCP query
                newQuery = dns.message.make_query(domain, dnsType, want_dnssec=False)
                response = dns.query.tcp(newQuery, res[i], timeout=10)
            except:
                continue
            if response:
                if response.answer:
                    if response.answer[0][0].rdtype == constCNAME:  # if the final response is CNAME type, resolving it again
                        cnameResponse = mydig(str(response.answer[0][0]), 'A')
                        response.answer += cnameResponse.answer
                return response
    return None


if __name__ == '__main__':
    domain = sys.argv[1]  # Taking the input arguments

    start_time = time.time()
    res = mydig(domain, 'A')  # Calling the mydig() and tracking the time
    end_time = time.time()

    elapsed_time = (end_time - start_time) * 1000

    if res:  # printing the final answer
        print('QUESTION SECTION:')
        print(res.question[0].to_text(), '\n')
        print('ANSWER SECTION:')

        for ans in res.answer:
            print(ans.to_text())

        print('\nQuery time:', '{:.2f}'.format(elapsed_time), ' msec')
        print("WHEN: {}".format(time.ctime()))
        print('MSG SIZE rcvd:', sys.getsizeof(res))
    else:
        print('DNS Resolving Unsuccessful')
