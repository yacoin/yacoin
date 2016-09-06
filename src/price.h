//#ifdef WIN32

#ifndef PRICE_H
#define PRICE_H


    class CProvider
    {
    public:
        std::string
            sDomain,
            sPriceRatioKey,
            sApi;
        int
            nOffset;
        static const int
            //nOffset = DEFAULT_char_offset,
            nPort = DEFAULT_HTTP_PORT;
        //int
        //    nOffset;
        //    nPort,
    };
    extern std::vector< CProvider > vBTCtoYACProviders;
    extern std::vector< CProvider > vUSDtoBTCProviders;

    extern void initialize_price_vectors( int & nIndexBtcToYac, int & nIndexUsdToBtc );
    extern bool GetMyExternalWebPage1( int & nIndex, std::string & strBuffer, double & dPrice );
    extern bool GetMyExternalWebPage2( int & nIndex, std::string & strBuffer, double & dPrice );





#endif // PRICE_H
 //#endif // WIN32
