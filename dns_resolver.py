import sys
import dns.resolver
import dns.query
import time

constSOA = dns.rdatatype.SOA
constCNAME = dns.rdatatype.CNAME


def exploreResponse(response, server, dnsType):
    if response[0].answer:  # if answer field of response is not empty then return the server
        return [server]

    if response[0].authority and response[0].authority[0].rdtype == constSOA:  # if authority field of response is non-empty  and is of type SOA then return the server
        return [server]

    if response[0].additional:  # If answer and authority is empty then traverse the additional field and look for other IPs
        res = []
        for rr in response[0].additional:
            res.append(rr[0].to_text())
        return res

    if response[0].authority:  # if anything doesn't hit then it's the CNAME case
        return domainResolution(response[0].authority[0][0].to_text(), dnsType)

    return []


def getNextServers(query, dnsType, server):
    try:
        newQuery = dns.message.make_query(query, dnsType)  # making the TCP query
        response = dns.query.udp(newQuery, server, timeout=2)
    except:
        return None

    return exploreResponse([response], server, dnsType)  # if there's a valid response, calling the exploreResponse() to get next level servers


def domainResolution(domain, dnsType):
    dns_domain = dns.name.from_text(domain)
    domainList = str(dns_domain).split('.')[::-1][1::]  # splitting the domain and reversing it
    currServers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241',
                   '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
                   '202.12.27.33']

    query = ''

    for i in range(len(domainList)):  # traversing the subdomains
        query = domainList[i] + '.' + query
        nextServers = []
        for j in range(len(currServers)):
            nextServers = getNextServers(query, dnsType, currServers[j])  # getting the next level servers
            if nextServers:
                break
        if not nextServers:
            return []
        currServers = nextServers  # assigning the curr level servers to next level servers
    return currServers


def mydig(domain, dnsType):
    res = domainResolution(domain, dnsType)  # calling the function which will give back the final list of servers
    if res:
        for i in range(len(res)):
            try:  # making the TCP query
                newQuery = dns.message.make_query(domain, dnsType)
                response = dns.query.udp(newQuery, res[i], timeout=2)
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
    dnsType = sys.argv[2]

    start_time = time.time()
    res = mydig(domain, dnsType)  # Calling the mydig() and tracking the time
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
