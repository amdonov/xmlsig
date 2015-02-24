package xmlsig
import "errors"

// Taken largely from an example in "Programming In Go"
// Keeping it separate from my stuff
type Stack []interface{}

func (stack *Stack) Len() int {
    return len(*stack)
}

func (stack *Stack) Push(x interface{}) {
    *stack = append(*stack, x)
}

func (stack *Stack) Top() (interface{}, error) {
    if len(*stack) == 0 {
        return nil, errors.New("Empty stack")
    }
    return (*stack)[stack.Len()-1], nil
}

func (stack *Stack) Pop() (interface{}, error) {
    theStack := *stack
    if (len(theStack)==0) {
        return nil, errors.New("Empty stack")
    }
    x := theStack[len(theStack)-1]
    *stack = theStack[:len(theStack)-1]
    return x, nil
}
