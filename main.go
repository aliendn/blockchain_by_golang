package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Block struct {
	Index        int           `json:"index"`
	Timestamp    int64         `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	Proof        int           `json:"proof"`
	PreviousHash string        `json:"previous_hash"`
}

type Transaction struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Amount    int    `json:"amount"`
}

type Blockchain struct {
	Chain               []Block
	CurrentTransactions []Transaction
	Nodes               map[string]struct{}
	mux                 sync.Mutex
}

func NewBlockchain() *Blockchain {
	bc := &Blockchain{Nodes: make(map[string]struct{})}
	bc.NewBlock(100, "1")
	return bc
}

func (bc *Blockchain) RegisterNode(address string) error {
	parsedURL, err := url.Parse(address)
	if err != nil {
		return err
	}

	if parsedURL.Host != "" {
		bc.Nodes[parsedURL.Host] = struct{}{}
	} else if parsedURL.Path != "" {
		bc.Nodes[parsedURL.Path] = struct{}{}
	} else {
		return fmt.Errorf("invalid URL")
	}

	return nil
}

func (bc *Blockchain) ValidChain(chain []Block) bool {
	lastBlock := chain[0]
	currentIndex := 1

	for currentIndex < len(chain) {
		block := chain[currentIndex]

		if block.PreviousHash != bc.Hash(lastBlock) {
			return false
		}

		if !bc.ValidProof(lastBlock.Proof, block.Proof, lastBlock.PreviousHash) {
			return false
		}

		lastBlock = block
		currentIndex++
	}

	return true
}

func (bc *Blockchain) ResolveConflicts() bool {
	bc.mux.Lock()
	defer bc.mux.Unlock()

	neighbours := bc.Nodes
	newChain := []Block{}
	maxLength := len(bc.Chain)

	for node := range neighbours {
		response, err := http.Get("http://" + node + "/chain")
		if err != nil {
			continue
		}
		defer response.Body.Close()

		if response.StatusCode == http.StatusOK {
			var data struct {
				Length int     `json:"length"`
				Chain  []Block `json:"chain"`
			}

			body, err := io.ReadAll(response.Body)
			if err != nil {
				continue
			}
			if err := json.Unmarshal(body, &data); err != nil {
				continue
			}

			if data.Length > maxLength && bc.ValidChain(data.Chain) {
				maxLength = data.Length
				newChain = data.Chain
			}
		}
	}

	if len(newChain) > 0 {
		bc.Chain = newChain
		return true
	}

	return false
}

func (bc *Blockchain) NewBlock(proof int, previousHash string) Block {
	block := Block{
		Index:        len(bc.Chain) + 1,
		Timestamp:    time.Now().Unix(),
		Transactions: bc.CurrentTransactions,
		Proof:        proof,
		PreviousHash: previousHash,
	}

	bc.CurrentTransactions = nil
	bc.Chain = append(bc.Chain, block)
	return block
}

func (bc *Blockchain) NewTransaction(sender, recipient string, amount int) int {
	transaction := Transaction{
		Sender:    sender,
		Recipient: recipient,
		Amount:    amount,
	}

	bc.CurrentTransactions = append(bc.CurrentTransactions, transaction)
	return bc.LastBlock().Index + 1
}

func (bc *Blockchain) LastBlock() *Block {
	return &bc.Chain[len(bc.Chain)-1]
}

func (bc *Blockchain) Hash(block Block) string {
	blockData, _ := json.Marshal(block)
	hash := sha256.Sum256(blockData)
	return fmt.Sprintf("%x", hash)
}

func (bc *Blockchain) ProofOfWork(lastBlock Block) int {
	lastProof := lastBlock.Proof
	lastHash := bc.Hash(lastBlock)

	proof := 0
	for !bc.ValidProof(lastProof, proof, lastHash) {
		proof++
	}

	return proof
}

func (bc *Blockchain) ValidProof(lastProof, proof int, lastHash string) bool {
	guess := fmt.Sprintf("%d%d%s", lastProof, proof, lastHash)
	guessHash := sha256.Sum256([]byte(guess))
	return guessHash[0] == 0 && guessHash[1] == 0 && guessHash[2] == 0 && guessHash[3] == 0
}

func main() {
	bc := NewBlockchain()
	nodeIdentifier := uuid.New().String()

	router := gin.Default()

	router.GET("/mine", func(c *gin.Context) {
		lastBlock := bc.LastBlock()
		proof := bc.ProofOfWork(*lastBlock)

		bc.NewTransaction("0", nodeIdentifier, 1)

		previousHash := bc.Hash(*lastBlock)
		block := bc.NewBlock(proof, previousHash)

		response := gin.H{
			"message":       "New Block Forged",
			"index":         block.Index,
			"transactions":  block.Transactions,
			"proof":         block.Proof,
			"previous_hash": block.PreviousHash,
		}
		c.JSON(http.StatusOK, response)
	})

	router.POST("/transactions/new", func(c *gin.Context) {
		var t Transaction
		if err := c.ShouldBindJSON(&t); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		index := bc.NewTransaction(t.Sender, t.Recipient, t.Amount)
		response := gin.H{"message": fmt.Sprintf("Transaction will be added to Block %d", index)}
		c.JSON(http.StatusCreated, response)
	})

	router.GET("/chain", func(c *gin.Context) {
		response := gin.H{
			"chain":  bc.Chain,
			"length": len(bc.Chain),
		}
		c.JSON(http.StatusOK, response)
	})

	router.POST("/nodes/register", func(c *gin.Context) {
		var data struct {
			Nodes []string `json:"nodes"`
		}
		if err := c.ShouldBindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if len(data.Nodes) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Please supply a valid list of nodes"})
			return
		}

		for _, node := range data.Nodes {
			if err := bc.RegisterNode(node); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
		}

		response := gin.H{
			"message":     "New nodes have been added",
			"total_nodes": bc.Nodes,
		}
		c.JSON(http.StatusCreated, response)
	})

	router.GET("/nodes/resolve", func(c *gin.Context) {
		replaced := bc.ResolveConflicts()

		var response gin.H
		if replaced {
			response = gin.H{
				"message":   "Our chain was replaced",
				"new_chain": bc.Chain,
			}
		} else {
			response = gin.H{
				"message": "Our chain is authoritative",
				"chain":   bc.Chain,
			}
		}

		c.JSON(http.StatusOK, response)
	})

	router.Run(":5000")
}
