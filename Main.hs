{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}

module Main where 

import Network.Pcap
import System.Environment (getArgs)
import Control.Applicative
import Control.Monad hiding (join)
import Control.Arrow (second)
import qualified Data.ByteString as B
import Data.ByteString.Char8 (singleton)
import qualified Data.Attoparsec.ByteString as A
import Data.Attoparsec.Combinator (count)
import Data.Int (Int64)
import Data.IORef
import Data.Maybe (fromMaybe)
import Data.List (find)
import qualified Data.Set as S

data Offer = Offer B.ByteString B.ByteString deriving (Show, Eq, Ord)

data QuotePacket = Packet { time      :: B.ByteString
                          , issueCode :: B.ByteString
                          , bids      :: [Offer]
                          , asks      :: [Offer]
                          }
    deriving (Show, Eq, Ord)

type PktTime = Int64
type TimedQuotePkt = (QuotePacket, PktTime)
type PcapState = (TimedQuotePkt, S.Set TimedQuotePkt, S.Set TimedQuotePkt)

parseOffer :: A.Parser Offer
parseOffer = Offer <$> price <*> qty
    where price = dropZeroes <$> A.take 5
          qty   = dropZeroes <$> A.take 7
          dropZeroes s = let res = B.dropWhile (== 48) s in if B.null res then "0" else res

parsePacket :: A.Parser QuotePacket
parsePacket = do
    A.take 42
    A.string "B6034"
    issueCode <- A.take 12
    A.take 12
    bids <- count 5 parseOffer
    A.take 7
    asks <- count 5 parseOffer
    A.take 50
    time <- A.take 8
    A.word8 255
    return Packet {issueCode, bids, asks, time}

toRow :: QuotePacket -> B.ByteString
toRow Packet {..} = B.intercalate (singleton ' ') $ issueCode : bidStrs ++ askStrs ++ [time]
    where bidStrs = map offerStr $ reverse bids
          askStrs = map offerStr asks
          offerStr (Offer p q) = B.concat [q, "@", p]

printPacket :: QuotePacket -> IO ()
printPacket = B.putStrLn . toRow

whenRight :: (Monad m) => Either a b -> (b -> m ()) -> m ()
whenRight v f = either (const $ return ()) f v

onPacketParseSuccess :: (Monad m) => (QuotePacket -> m ()) -> B.ByteString -> m ()
onPacketParseSuccess f = flip whenRight f . A.parseOnly parsePacket

process :: PktHdr -> B.ByteString -> IO ()
process hdr = onPacketParseSuccess printPacket

processSet :: (IORef PcapState) -> PktHdr -> B.ByteString -> IO ()
processSet ref hdr s = whenRight (A.parseOnly parsePacket s) $ \newPkt -> do
    (pktTup@(waitingPkt, t0), befores, afters) <- readIORef ref
    let newTup@(_, newPktTime) = (newPkt, hdrTime hdr)
    if newPktTime - t0 > 3000000
        then do
            mapM_ (printPacket . fst) $ S.toAscList befores
            printPacket waitingPkt
            let (nextPktTup, newAfters) = second (S.insert newTup) $ S.deleteFindMin afters
            writeIORef ref (nextPktTup, S.empty, newAfters)
        else 
            writeIORef ref $ if time newPkt <= time waitingPkt
                then (pktTup, S.insert newTup befores, afters)
                else (pktTup, befores, S.insert newTup afters)

getFirstQuotePacket :: PcapHandle -> IO TimedQuotePkt
getFirstQuotePacket handle = do
    (hdr, s) <- nextBS handle
    case A.parseOnly parsePacket s of
        Left _ -> getFirstQuotePacket handle
        Right x -> return (x, hdrTime hdr)

outputUnordered :: PcapHandle -> IO ()
outputUnordered handle = void $ dispatchBS handle (-1) process

outputOrdered :: PcapHandle -> IO ()
outputOrdered handle = do
    p0  <- getFirstQuotePacket handle
    ref <- newIORef (p0, S.empty, S.empty)
    dispatchBS handle (-1) (processSet ref)
    (p, b, a) <- readIORef ref
    mapM_ (printPacket . fst) $ S.toAscList b
    printPacket $ fst p
    mapM_ (printPacket . fst) $ S.toAscList a

main = do
    args <- getArgs
    let path = fromMaybe (error "Provide the path of a dump-file") $ find (/= "-r") args
    handle <- openOffline path
    if "-r" `elem` args
        then outputOrdered handle
        else outputUnordered handle
